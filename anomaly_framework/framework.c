/*
 * framework.c -- Shared Anomaly-Detection Framework
 *
 * Description:
 * -----------
 *   Everything that is common to all detectors, written ONCE so each plugin
 *   only contains its own math:
 *     - CSV reading (streamed row-by-row, so memory does not grow with rows)
 *     - schema detection (header, feature columns, label column)
 *     - per-feature normalization (clamp -> log1p -> running z-score)
 *     - the per-row run loop that drives one AlgoOps vtable
 *     - raw + derived metric computation
 *
 * Parameters:
 * -----------
 *   Driven entirely by the Config struct passed to framework_run().
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <ctype.h>

#include "main.h"

/* ================================================================
 * Built-in default feature/label conventions per RunMode.
 * Overridable from the command line (-f features, -l label).
 * ================================================================ */
static const char *FLOW_FEATURES[] = {
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd Packet Length Mean", "PSH Flag Count", "ACK Flag Count"
};
static const char *TS_FEATURES[] = {
    "orig_bytes", "resp_bytes", "duration",
    "orig_pkts", "resp_pkts", "orig_ip_bytes"
};
#define FLOW_LABEL_COL  "Label"     /* default label column, flow mode */
#define TS_LABEL_COL    "label"     /* default label column, ts mode   */
#define BENIGN_TOKEN    "BENIGN"    /* anything else (case-insensitive) = anomaly */

/* ================================================================
 * Welford online mean/variance (used only for normalization here).
 * ================================================================ */
typedef struct {
    long   n;
    double mu;
    double M2;
} Welford;

/*
 * welford_update()
 *   Fold a new sample into running mean/variance (numerically stable).
 *   Parameters : w - Welford state
 *                x - new sample
 *   Return     : void
 */
static void welford_update(Welford *w, double x)
{
    w->n++;
    double d = x - w->mu;
    w->mu += d / w->n;
    w->M2 += d * (x - w->mu);
}

/*
 * welford_zscore()
 *   Standardize x against the running stats; 0.0 until 2 samples are seen.
 *   Parameters : w - Welford state
 *                x - value to standardize
 *   Return     : z-score, or 0.0 if fewer than 2 samples
 */
static double welford_zscore(const Welford *w, double x)
{
    if (w->n < 2)
        return 0.0;
    double std = sqrt(w->M2 / w->n);
    return (x - w->mu) / (std + EPSILON);
}

/* ================================================================
 * Small CSV helpers
 * ================================================================ */

/*
 * trim()
 *   Strip trailing whitespace/control characters in place.
 *   Parameters : s - null-terminated string to trim
 *   Return     : void
 */
static void trim(char *s)
{
    int len = (int)strlen(s);
    while (len > 0 && (unsigned char)s[len - 1] <= ' ')
        s[--len] = '\0';
}

/*
 * split_line()
 *   Split a comma-separated line into tokens (destroys the input).
 *   Parameters : line - mutable CSV line
 *                tok  - output token array
 *   Return     : number of tokens parsed (capped at MAX_COLS)
 */
static int split_line(char *line, char tok[][MAX_COL_LEN])
{
    int count = 0;
    char *p = strtok(line, ",");
    while (p && count < MAX_COLS) {
        strncpy(tok[count], p, MAX_COL_LEN - 1);
        tok[count][MAX_COL_LEN - 1] = '\0';
        count++;
        p = strtok(NULL, ",");
    }
    return count;
}

/*
 * find_col()
 *   Find a column index by exact header name.
 *   Parameters : headers - parsed header tokens
 *                n       - number of header tokens
 *                name    - column name to find
 *   Return     : column index, or -1 if absent
 */
static int find_col(char headers[][MAX_COL_LEN], int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (strcmp(headers[i], name) == 0)
            return i;
    return -1;
}

/*
 * safe_float()
 *   Parse a float defensively; empty/garbage/non-finite -> 0.0.
 *   Parameters : s - string to parse
 *   Return     : parsed finite double, or 0.0
 */
static double safe_float(const char *s)
{
    if (!s || s[0] == '\0')
        return 0.0;
    char *end;
    double v = strtod(s, &end);
    if (end == s || !isfinite(v))
        return 0.0;
    return v;
}

/* ================================================================
 * Shared helpers declared in main.h
 * ================================================================ */

double param_get(const ParamList *p, const char *key, double dflt)
{
    if (!p)
        return dflt;
    for (int i = 0; i < p->count; i++)
        if (strcmp(p->key[i], key) == 0)
            return isfinite(p->val[i]) ? p->val[i] : dflt;   /* invalid -> default */
    return dflt;
}

float composite_mean(const float *x, int n_features)
{
    if (n_features <= 0)
        return 0.0f;
    double sum = 0.0;
    for (int i = 0; i < n_features; i++)
        sum += x[i];
    return (float)(sum / n_features);
}

/* ================================================================
 * Metric finalization (raw counts -> derived figures)
 * ================================================================ */

/*
 * metrics_finalize()
 *   Compute derived metrics from the raw counters gathered in the run loop.
 *   Parameters : m - Metrics with raw fields populated
 *   Return     : void (derived fields filled in place)
 */
static void metrics_finalize(Metrics *m)
{
    double tp = (double)m->tp, fp = (double)m->fp;
    double fn = (double)m->fn, tn = (double)m->tn;

    m->precision   = (tp + fp) > 0 ? tp / (tp + fp) : 0.0;
    m->recall      = (tp + fn) > 0 ? tp / (tp + fn) : 0.0;   /* sensitivity */
    m->f1          = (m->precision + m->recall) > 0
                     ? 2.0 * m->precision * m->recall / (m->precision + m->recall)
                     : 0.0;
    m->specificity = (tn + fp) > 0 ? tn / (tn + fp) : 0.0;
    m->fpr         = (fp + tn) > 0 ? fp / (fp + tn) : 0.0;
    m->balanced_acc = 0.5 * (m->recall + m->specificity);

    /* Matthews Correlation Coefficient -- robust under heavy class imbalance. */
    double denom = sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn));
    m->mcc = denom > 0 ? (tp * tn - fp * fn) / denom : 0.0;

    m->mean_delay = m->events_caught > 0
                    ? (double)m->delay_sum / m->events_caught : 0.0;
    m->ns_per_update = m->rows > 0 ? m->update_ns / m->rows : 0.0;
    m->rows_per_sec  = m->update_ns > 0
                       ? m->rows / (m->update_ns / 1e9) : 0.0;
}

/* ================================================================
 * The run loop
 * ================================================================ */

int framework_run(const Config *cfg, const AlgoOps *ops, Metrics *out)
{
    FILE *f = fopen(cfg->datafile, "r");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", cfg->datafile);
        return 1;
    }

    /* ---- resolve feature/label schema for this mode ---- */
    const char **feat_names;
    int n_feat;
    char feat_buf[MAX_FEATURES][MAX_COL_LEN];
    const char *feat_ptr[MAX_FEATURES];

    if (cfg->feature_csv) {
        /* User-supplied feature list via -f. */
        char tmp[MAX_LINE];
        strncpy(tmp, cfg->feature_csv, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        n_feat = 0;
        char *p = strtok(tmp, ",");
        while (p && n_feat < MAX_FEATURES) {
            strncpy(feat_buf[n_feat], p, MAX_COL_LEN - 1);
            feat_buf[n_feat][MAX_COL_LEN - 1] = '\0';
            feat_ptr[n_feat] = feat_buf[n_feat];
            n_feat++;
            p = strtok(NULL, ",");
        }
        feat_names = feat_ptr;
    } else if (cfg->mode == MODE_FLOW) {
        feat_names = FLOW_FEATURES;
        n_feat = (int)(sizeof(FLOW_FEATURES) / sizeof(FLOW_FEATURES[0]));
    } else {
        feat_names = TS_FEATURES;
        n_feat = (int)(sizeof(TS_FEATURES) / sizeof(TS_FEATURES[0]));
    }

    const char *label_name = cfg->label_col
                             ? cfg->label_col
                             : (cfg->mode == MODE_FLOW ? FLOW_LABEL_COL : TS_LABEL_COL);

    /* ---- read header, map columns to indices ---- */
    char line[MAX_LINE];
    char tok[MAX_COLS][MAX_COL_LEN];

    if (!fgets(line, sizeof(line), f)) {
        fprintf(stderr, "Empty file: %s\n", cfg->datafile);
        fclose(f);
        return 1;
    }
    trim(line);
    int ncols = split_line(line, tok);

    int fidx[MAX_FEATURES];
    for (int i = 0; i < n_feat; i++)
        fidx[i] = find_col(tok, ncols, feat_names[i]);
    int lidx = find_col(tok, ncols, label_name);

    /* ---- init algorithm + per-feature normalizers ---- */
    void *ctx = ops->init(n_feat, &cfg->params, cfg->mode);
    if (!ctx) {
        fprintf(stderr, "Algorithm init failed\n");
        fclose(f);
        return 1;
    }

    Welford norms[MAX_FEATURES];
    memset(norms, 0, sizeof(norms));

    memset(out, 0, sizeof(*out));

    /* Event tracking for detection-delay metric. */
    int in_event = 0;        /* currently inside a true-anomaly segment */
    int event_caught = 0;    /* this segment already detected           */
    long rows_into_event = 0;

    /* ---- stream rows ---- */
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '\0')
            continue;
        int tc = split_line(line, tok);

        /* Ground-truth label: anything but the benign token = anomaly. */
        int label = 0;
        if (lidx >= 0 && lidx < tc)
            label = (strcasecmp(tok[lidx], BENIGN_TOKEN) != 0);

        /* Build the normalized feature vector for this row. */
        float x[MAX_FEATURES];
        int valid = 0;
        for (int i = 0; i < n_feat; i++) {
            if (fidx[i] < 0 || fidx[i] >= tc)
                continue;
            double raw = safe_float(tok[fidx[i]]);
            if (raw < NORM_CLAMP_MIN)
                raw = NORM_CLAMP_MIN;

            double v = cfg->normalize ? log1p(raw) : raw;
            if (cfg->normalize) {
                welford_update(&norms[i], v);
                v = welford_zscore(&norms[i], v);
            }
            x[valid++] = (float)v;
        }

        /* Drive the algorithm and time only the update() call. */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int pred = ops->update(ctx, x, valid);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        out->update_ns += (t1.tv_sec - t0.tv_sec) * 1e9
                        + (t1.tv_nsec - t0.tv_nsec);

        out->rows++;

        /* Confusion-matrix counts (per row). */
        if (pred && label)        out->tp++;
        else if (pred && !label)  out->fp++;
        else if (!pred && label)  out->fn++;
        else                      out->tn++;

        /* Per-event detection delay tracking. */
        if (label) {
            if (!in_event) {              /* new anomaly segment begins */
                in_event = 1;
                event_caught = 0;
                rows_into_event = 0;
                out->n_events++;
            }
            if (pred && !event_caught) {  /* first detection in this segment */
                event_caught = 1;
                out->events_caught++;
                out->delay_sum += rows_into_event;
            }
            rows_into_event++;
        } else {
            in_event = 0;                 /* segment ended */
        }
    }

    out->model_bytes = ops->model_bytes(ctx);
    ops->destroy(ctx);
    fclose(f);

    metrics_finalize(out);
    return 0;
}
