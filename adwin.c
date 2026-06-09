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

#define ADWIN_MAX_WINDOW 512

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
    double window[ADWIN_MAX_WINDOW];
    int head;
    int size;
    double delta;
    long total_n;
} ADWIN;

void adwin_init(ADWIN *a, double delta) {
    memset(a, 0, sizeof(ADWIN));
    a->delta = delta;
}

static double get_at(ADWIN *a, int idx) {
    return a->window[(a->head + idx) % ADWIN_MAX_WINDOW];
}

int adwin_update(ADWIN *a, double x) {

    a->total_n++;

    if (a->size < ADWIN_MAX_WINDOW) {

        int pos =
            (a->head + a->size) %
            ADWIN_MAX_WINDOW;

        a->window[pos] = x;
        a->size++;

    } else {

        a->window[a->head] = x;
        a->head =
            (a->head + 1) %
            ADWIN_MAX_WINDOW;
    }

    if (a->size < 16)
        return 0;

    double total_sum = 0.0;

    for (int i = 0; i < a->size; i++)
        total_sum += get_at(a, i);

    double prefix = 0.0;

    for (int k = 8; k < a->size - 8; k *= 2) {

        for (int i = k / 2; i < k; i++)
            prefix += get_at(a, i);

        int n0 = k;
        int n1 = a->size - k;

        double mu0 = prefix / n0;
        double mu1 =
            (total_sum - prefix) / n1;

        double m =
            (double)(n0 * n1) /
            (n0 + n1);

        double eps =
            sqrt((1.0 / (2.0 * m)) *
            log(4.0 * a->total_n /
            a->delta));

        if (fabs(mu0 - mu1) > eps)
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
    while (len > 0 &&
          ((unsigned char)s[len - 1] <= 32))
        s[--len] = '\0';
}

static int split_line(char *line,
                      char tok[][MAX_COL_LEN]) {

    int count = 0;

    char *p = strtok(line, ",");

    while (p && count < MAX_COLS) {

        strncpy(tok[count],
                p,
                MAX_COL_LEN - 1);

        tok[count][MAX_COL_LEN - 1] = '\0';

        count++;

        p = strtok(NULL, ",");
    }

    return count;
}

static int find_col(char headers[][MAX_COL_LEN],
                    int n,
                    const char *name) {

    for (int i = 0; i < n; i++)
        if (strcmp(headers[i], name) == 0)
            return i;

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

        composite +=
            welford_norm(&norms[i], v);

        valid++;
    }

    return valid
           ? composite / valid
           : 0.0;
}

static void run_detector(const char *path,
                         int is_flow) {

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
            fidx[i] =
                find_col(tok,
                         ncols,
                         FLOW_FEAT[i]);
    } else {
        for (int i = 0; i < TS_N_FEAT; i++)
            fidx[i] =
                find_col(tok,
                         ncols,
                         TS_FEAT[i]);
    }

    int lidx =
        find_col(tok,
                 ncols,
                 is_flow ? "Label" : "label");

    Row rows[MAX_ROWS];

    Welford norms[6];
    memset(norms, 0, sizeof(norms));

    int n = 0;

    while (fgets(line, sizeof(line), f)
           && n < MAX_ROWS) {

        trim(line);

        int tc = split_line(line, tok);

        int label = 0;

        if (is_flow)
            label =
                (strcasecmp(tok[lidx],
                "BENIGN") != 0);
        else
            label =
                (strcasecmp(tok[lidx],
                "Benign") != 0);

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

    ADWIN a;

    if (is_flow)
        adwin_init(&a, 0.002);
    else
        adwin_init(&a, 0.001);

    int tp = 0;
    int fp = 0;
    int fn = 0;

    clock_t t0 = clock();

    for (int i = 0; i < n; i++) {

        int pred =
            adwin_update(&a,
                         rows[i].value);

        if (pred && rows[i].label)
            tp++;
        else if (pred && !rows[i].label)
            fp++;
        else if (!pred && rows[i].label)
            fn++;
    }

    double elapsed =
        1000.0 *
        (clock() - t0) /
        CLOCKS_PER_SEC;

    double precision =
        (tp + fp)
        ? (double)tp / (tp + fp)
        : 0.0;

    double recall =
        (tp + fn)
        ? (double)tp / (tp + fn)
        : 0.0;

    double f1 =
        (precision + recall)
        ? 2.0 * precision * recall /
          (precision + recall)
        : 0.0;

    printf("ADWIN RESULTS\n");
    printf("Rows        : %d\n", n);
    printf("TP           : %d\n", tp);
    printf("FP           : %d\n", fp);
    printf("FN           : %d\n", fn);
    printf("Precision    : %.4f\n", precision);
    printf("Recall       : %.4f\n", recall);
    printf("F1 Score     : %.4f\n", f1);
    printf("Time         : %.2f ms\n", elapsed);
    printf("Memory       : %lu bytes\n",
           sizeof(ADWIN));
}

int main(int argc, char *argv[]) {

    if (argc < 3) {

        printf("Usage:\n");
        printf("./adwin flow dataset.csv\n");
        printf("./adwin ts dataset.csv\n");

        return 1;
    }

    int is_flow =
        strcmp(argv[1], "flow") == 0;

    run_detector(argv[2], is_flow);

    return 0;
}