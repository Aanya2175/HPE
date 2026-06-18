/*
 * anomaly_detector.c -- Common Framework Driver (entry point)
 *
 * Description:
 * -----------
 *   Parses command-line arguments, builds a Config, selects one or all
 *   registered algorithms, runs each through the shared framework, and prints
 *   a grouped human-readable metrics report (optionally JSON via -j).
 *
 *   Usage:
 *     ./anomaly_detector [options] DATAFILE.csv
 *
 *   Options:
 *     -a NAME    algorithm to run, or "all" (default: all)
 *     -m MODE    flow | ts  -> selects default parameter profile (default: flow)
 *     -f LIST    comma-separated feature column names (default: mode built-ins)
 *     -l NAME    label column name (default: "Label" for flow, "label" for ts)
 *     -p PARAMS  comma-separated key=val overrides, e.g. threshold=5.5,drift=0.08
 *     -r         use RAW features (skip log1p + z-score normalization)
 *     -j         also print machine-readable JSON
 *     -h         show this help
 *
 * Parameters:
 * -----------
 *   See option list above.
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>     /* NAN */
#include <unistd.h>     /* getopt */

#include "main.h"

/*
 * parse_params()
 *   Parse a "-p key=val,key=val,..." string into a ParamList.
 *   Parameters : s   - raw parameter string (may be NULL)
 *                out - ParamList to populate
 *   Return     : void
 */
static void parse_params(const char *s, ParamList *out)
{
    out->count = 0;
    if (!s)
        return;

    char buf[MAX_LINE];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *pair = strtok(buf, ",");
    while (pair && out->count < MAX_PARAMS) {
        char *eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            strncpy(out->key[out->count], pair, MAX_COL_LEN - 1);
            out->key[out->count][MAX_COL_LEN - 1] = '\0';

            /* Parse the value; if nothing numeric was consumed, store NAN so
             * param_get() treats it as invalid and falls back to the default. */
            char  *end;
            double v = strtod(eq + 1, &end);
            out->val[out->count] = (end == eq + 1) ? NAN : v;
            out->count++;
        }
        pair = strtok(NULL, ",");
    }
}

/*
 * print_report()
 *   Print one algorithm's metrics as a grouped, sectioned table.
 *   Parameters : name - algorithm name
 *                m    - finalized Metrics
 *   Return     : void
 */
static void print_report(const char *name, const Metrics *m)
{
    printf("\n================ %s ================\n", name);

    printf("[Dataset]\n");
    printf("  Rows processed     : %ld\n", m->rows);
    printf("  Anomaly events     : %ld\n", m->n_events);

    printf("[Confusion matrix - raw]\n");
    printf("  TP / FP            : %ld / %ld\n", m->tp, m->fp);
    printf("  FN / TN            : %ld / %ld\n", m->fn, m->tn);

    printf("[Detection quality - derived]\n");
    printf("  Precision          : %.4f\n", m->precision);
    printf("  Recall             : %.4f\n", m->recall);
    printf("  F1 score           : %.4f\n", m->f1);
    printf("  Specificity        : %.4f\n", m->specificity);
    printf("  False-positive rate: %.4f\n", m->fpr);
    printf("  Balanced accuracy  : %.4f\n", m->balanced_acc);
    printf("  MCC                : %.4f\n", m->mcc);

    printf("[Responsiveness - derived]\n");
    printf("  Events caught      : %ld / %ld\n", m->events_caught, m->n_events);
    printf("  Mean detect delay  : %.2f rows\n", m->mean_delay);

    printf("[Cost - raw + derived]\n");
    printf("  Model memory       : %zu bytes\n", m->model_bytes);
    printf("  Latency per update : %.1f ns\n", m->ns_per_update);
    printf("  Throughput         : %.0f rows/s\n", m->rows_per_sec);
}

/*
 * print_json()
 *   Emit one algorithm's metrics as a single JSON object (one per line) so a
 *   benchmark harness or plotting script can ingest results directly.
 *   Parameters : name - algorithm name
 *                m    - finalized Metrics
 *   Return     : void
 */
static void print_json(const char *name, const Metrics *m)
{
    printf("{\"algo\":\"%s\",\"rows\":%ld,\"tp\":%ld,\"fp\":%ld,\"fn\":%ld,"
           "\"tn\":%ld,\"precision\":%.6f,\"recall\":%.6f,\"f1\":%.6f,"
           "\"specificity\":%.6f,\"fpr\":%.6f,\"balanced_acc\":%.6f,"
           "\"mcc\":%.6f,\"events\":%ld,\"events_caught\":%ld,"
           "\"mean_delay\":%.4f,\"model_bytes\":%zu,\"ns_per_update\":%.4f,"
           "\"rows_per_sec\":%.2f}\n",
           name, m->rows, m->tp, m->fp, m->fn, m->tn,
           m->precision, m->recall, m->f1, m->specificity, m->fpr,
           m->balanced_acc, m->mcc, m->n_events, m->events_caught,
           m->mean_delay, m->model_bytes, m->ns_per_update, m->rows_per_sec);
}

/*
 * usage()
 *   Print usage help.
 *   Parameters : prog - argv[0]
 *   Return     : void
 */
static void usage(const char *prog)
{
    printf("Usage: %s [-a NAME|all] [-m flow|ts] [-f feat,..] [-l label]\n"
           "          [-p key=val,..] [-r] [-j] DATAFILE.csv\n", prog);
}

int main(int argc, char *argv[])
{
    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = MODE_FLOW;
    cfg.normalize = 1;          /* normalization on by default */

    const char *algo = "all";
    const char *params = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "a:m:f:l:p:rjh")) != -1) {
        switch (opt) {
            case 'a': algo = optarg; break;
            case 'm': cfg.mode = (strcmp(optarg, "ts") == 0) ? MODE_TS : MODE_FLOW; break;
            case 'f': cfg.feature_csv = optarg; break;
            case 'l': cfg.label_col = optarg; break;
            case 'p': params = optarg; break;
            case 'r': cfg.normalize = 0; break;
            case 'j': cfg.json = 1; break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: no data file given.\n");
        usage(argv[0]);
        return 1;
    }
    cfg.datafile = argv[optind];
    parse_params(params, &cfg.params);

    /* Build the list of algorithms to run. */
    const AlgoOps *run_set[64];
    int n_run = 0;

    if (strcmp(algo, "all") == 0) {
        const AlgoOps *a;
        for (int i = 0; (a = registry_at(i)) != NULL && n_run < 64; i++)
            run_set[n_run++] = a;
    } else {
        const AlgoOps *a = registry_find(algo);
        if (!a) {
            fprintf(stderr, "Unknown algorithm: %s\n", algo);
            return 1;
        }
        run_set[n_run++] = a;
    }

    /* Run each algorithm through the shared framework. */
    for (int i = 0; i < n_run; i++) {
        Metrics m;
        if (framework_run(&cfg, run_set[i], &m) != 0)
            return 1;
        print_report(run_set[i]->name, &m);
        if (cfg.json)
            print_json(run_set[i]->name, &m);
    }

    return 0;
}
