#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <ctype.h>

#define MAX_COLS 128
#define MAX_COL_LEN 128
#define MAX_LINE 16384
#define MAX_ROWS 50000

#define FLOW_N_FEAT 6
#define TS_N_FEAT   6

#define WARMUP_SAMPLES 30
#define DETECT_WINDOW  5

typedef struct {
    long n;
    double mu;
    double M2;
} Welford;

static void welford_update(Welford *w, double x) {
    w->n++;
    double d = x - w->mu;
    w->mu += d / w->n;
    w->M2 += d * (x - w->mu);
}

static double welford_norm(Welford *w, double x) {
    if (w->n < 2) return 0.0;
    double std = sqrt(w->M2 / w->n);
    return (x - w->mu) / (std + 1e-9);
}

typedef struct {
    double threshold;
    double drift;
    double pos_sum;
    double neg_sum;
    double mu;
    double sigma;
    double M2;
    long n;
    int ready;
} CUSUM;

void cusum_init(CUSUM *c, double threshold, double drift) {
    memset(c, 0, sizeof(CUSUM));
    c->threshold = threshold;
    c->drift = drift;
}

int cusum_update(CUSUM *c, double x) {

    c->n++;

    double delta = x - c->mu;
    c->mu += delta / c->n;
    c->M2 += delta * (x - c->mu);

    if (c->n < WARMUP_SAMPLES)
        return 0;

    c->sigma = sqrt(c->M2 / c->n);

    double z = (x - c->mu) / (c->sigma + 1e-9);

    c->mu = 0.995 * c->mu + 0.005 * x;

    c->pos_sum += z - c->drift;
    if (c->pos_sum < 0.0)
        c->pos_sum = 0.0;

    c->neg_sum += -z - c->drift;
    if (c->neg_sum < 0.0)
        c->neg_sum = 0.0;

    if (c->pos_sum > c->threshold ||
        c->neg_sum > c->threshold) {

        c->pos_sum *= 0.5;
        c->neg_sum *= 0.5;
        return 1;
    }

    return 0;
}

static const char *FLOW_FEAT[FLOW_N_FEAT] = {
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Fwd Packet Length Mean",
    "PSH Flag Count",
    "ACK Flag Count"
};

static const char *TS_FEAT[TS_N_FEAT] = {
    "orig_bytes",
    "resp_bytes",
    "duration",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes"
};

typedef struct {
    double value;
    int label;
} Row;

static void trim(char *s) {
    int len = strlen(s);
    while (len > 0 && ((unsigned char)s[len - 1] <= 32))
        s[--len] = '\0';
}

static int split_line(char *line, char tok[][MAX_COL_LEN]) {

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

static int find_col(char headers[][MAX_COL_LEN],
                    int n,
                    const char *name) {

    for (int i = 0; i < n; i++) {
        if (strcmp(headers[i], name) == 0)
            return i;
    }

    return -1;
}

static double safe_float(const char *s) {

    if (!s || s[0] == '\0')
        return 0.0;

    char *end;
    double v = strtod(s, &end);

    if (end == s || !isfinite(v))
        return 0.0;

    return v;
}

static double build_composite(char tok[][MAX_COL_LEN],
                              int tc,
                              int *fidx,
                              int nfeat,
                              Welford *norms) {

    double composite = 0.0;
    int valid = 0;

    for (int i = 0; i < nfeat; i++) {

        if (fidx[i] < 0 || fidx[i] >= tc)
            continue;

        double raw = safe_float(tok[fidx[i]]);

        if (raw < 0.0)
            raw = 0.0;

        double v = log1p(raw);

        welford_update(&norms[i], v);

        composite += welford_norm(&norms[i], v);

        valid++;
    }

    return valid ? composite / valid : 0.0;
}

static void run_detector(const char *path, int is_flow) {

    FILE *f = fopen(path, "r");

    if (!f) {
        printf("Cannot open file\n");
        return;
    }

    char line[MAX_LINE];
    char tok[MAX_COLS][MAX_COL_LEN];

    fgets(line, sizeof(line), f);
    trim(line);

    int ncols = split_line(line, tok);

    int fidx[6];

    if (is_flow) {
        for (int i = 0; i < FLOW_N_FEAT; i++)
            fidx[i] = find_col(tok, ncols, FLOW_FEAT[i]);
    } else {
        for (int i = 0; i < TS_N_FEAT; i++)
            fidx[i] = find_col(tok, ncols, TS_FEAT[i]);
    }

    int lidx = find_col(tok, ncols,
                        is_flow ? "Label" : "label");

    Row rows[MAX_ROWS];

    Welford norms[6];
    memset(norms, 0, sizeof(norms));

    int n = 0;

    while (fgets(line, sizeof(line), f) && n < MAX_ROWS) {

        trim(line);

        int tc = split_line(line, tok);

        int label = 0;

        if (is_flow)
            label = (strcasecmp(tok[lidx], "BENIGN") != 0);
        else
            label = (strcasecmp(tok[lidx], "Benign") != 0);

        double composite =
            build_composite(tok,
                            tc,
                            fidx,
                            6,
                            norms);

        rows[n].value = composite;
        rows[n].label = label;

        n++;
    }

    fclose(f);

    CUSUM c;

    if (is_flow)
        cusum_init(&c, 5.5, 0.08);
    else
        cusum_init(&c, 5.0, 0.05);

    int tp = 0;
    int fp = 0;
    int fn = 0;

    clock_t t0 = clock();

    for (int i = 0; i < n; i++) {

        int pred = cusum_update(&c, rows[i].value);

        if (pred && rows[i].label)
            tp++;
        else if (pred && !rows[i].label)
            fp++;
        else if (!pred && rows[i].label)
            fn++;
    }

    double elapsed =
        1000.0 * (clock() - t0) / CLOCKS_PER_SEC;

    double precision =
        (tp + fp) ? (double)tp / (tp + fp) : 0.0;

    double recall =
        (tp + fn) ? (double)tp / (tp + fn) : 0.0;

    double f1 =
        (precision + recall)
        ? 2.0 * precision * recall /
          (precision + recall)
        : 0.0;

    printf("CUSUM RESULTS\n");
    printf("Rows        : %d\n", n);
    printf("TP           : %d\n", tp);
    printf("FP           : %d\n", fp);
    printf("FN           : %d\n", fn);
    printf("Precision    : %.4f\n", precision);
    printf("Recall       : %.4f\n", recall);
    printf("F1 Score     : %.4f\n", f1);
    printf("Time         : %.2f ms\n", elapsed);
    printf("Memory       : O(1)\n");
}

int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage:\n");
        printf("./cusum flow dataset.csv\n");
        printf("./cusum ts dataset.csv\n");
        return 1;
    }

    int is_flow =
        strcmp(argv[1], "flow") == 0;

    run_detector(argv[2], is_flow);

    return 0;
}