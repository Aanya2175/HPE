/*
 * main.h -- Common Framework Contract for Streaming Anomaly Detectors
 *
 * Description:
 * -----------
 *   Single shared header included by the driver (anomaly_detector.c), the
 *   shared framework (framework.c), and EVERY per-algorithm plugin
 *   (cusum_algo.c, adwin_algo.c, ...). It defines:
 *     - global configuration macros (CSV limits, numeric epsilon)
 *     - shared data types (RunMode, ParamList, Config, AlgoOps, Metrics)
 *     - declarations of helpers implemented once in framework.c
 *
 *   An algorithm plugs in by implementing the AlgoOps vtable. The framework
 *   owns all CSV parsing, feature normalization, the per-row loop and metric
 *   computation, so a plugin contains ONLY its own math.
 *
 * Parameters:
 * -----------
 *   Compile-time macros below are global. Per-algorithm default parameters
 *   live in each algorithm's own header (e.g. cusum.h, adwin.h).
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#ifndef MAIN_H
#define MAIN_H

#include <stddef.h>     /* size_t */

/* ================================================================
 * Global limits and numeric constants (shared by all algorithms)
 * ================================================================ */

#define MAX_COLS        128     /* Maximum CSV columns supported            */
#define MAX_COL_LEN     128     /* Maximum length of one column name/value  */
#define MAX_LINE        16384   /* Maximum raw CSV line length in bytes      */
#define MAX_FEATURES     64     /* Maximum feature columns fed to an algo    */
#define MAX_PARAMS       32     /* Maximum key=value pairs accepted via -p   */
#define EPSILON         1e-9    /* Guard added to denominators / std-dev     */

#define NORM_CLAMP_MIN   0.0    /* Negative raw feature values clamped here  */

/* ================================================================
 * RunMode -- selects an algorithm's default parameter profile.
 * The detection LOGIC is identical for both; only default thresholds
 * (and the dataset's column/label conventions) differ.
 * ================================================================ */
typedef enum {
    MODE_FLOW = 0,   /* CICIDS-style flow CSV   (label col "Label")  */
    MODE_TS   = 1    /* Zeek-style time-series  (label col "label")  */
} RunMode;

/* ================================================================
 * ParamList -- parsed result of "-p key=val,key=val,..."
 * Algorithms read what they recognise via param_get().
 * ================================================================ */
typedef struct {
    char   key[MAX_PARAMS][MAX_COL_LEN];  /* parameter names                */
    double val[MAX_PARAMS];               /* parameter values               */
    int    count;                         /* number of pairs parsed          */
} ParamList;

/* ================================================================
 * Config -- everything the driver hands to the framework run loop.
 * ================================================================ */
typedef struct {
    const char *datafile;     /* path to CSV (required, positional arg)      */
    RunMode     mode;         /* MODE_FLOW or MODE_TS (-m)                    */
    const char *feature_csv;  /* comma list from -f, or NULL for mode default*/
    const char *label_col;    /* label column name (-l), or NULL for default */
    ParamList   params;       /* parsed -p key=val list                      */
    int         normalize;    /* 1 = apply log1p + running z-score (default) */
    int         json;         /* 1 = also emit machine-readable JSON         */
} Config;

/* ================================================================
 * AlgoOps -- the vtable every algorithm plugin implements.
 * ================================================================ */
typedef struct {
    const char *name;   /* selector matched against -a NAME                  */

    /*
     * init()
     *   Allocate and configure the algorithm context.
     *   Parameters : n_features - number of features each update receives
     *                params     - parsed -p list (read defaults via param_get)
     *                mode       - MODE_FLOW / MODE_TS (selects default profile)
     *   Return     : opaque context pointer, or NULL on allocation failure
     */
    void  *(*init)(int n_features, const ParamList *params, RunMode mode);

    /*
     * update()
     *   Feed ONE normalized feature vector and get the decision.
     *   Parameters : ctx        - context returned by init()
     *                x          - normalized feature vector (length n_features)
     *                n_features - number of valid entries in x
     *   Return     : 1 if anomaly, 0 if normal
     */
    int    (*update)(void *ctx, const float *x, int n_features);

    /*
     * score()
     *   Anomaly score of the LAST update() call. Threshold-free, used for
     *   ROC/PR analysis (higher = more anomalous).
     *   Parameters : ctx - context returned by init()
     *   Return     : anomaly score of the most recent sample
     */
    float  (*score)(void *ctx);

    /*
     * model_bytes()
     *   Steady-state memory held by the model (for the benchmark table).
     *   Parameters : ctx - context returned by init()
     *   Return     : number of bytes the model occupies
     */
    size_t (*model_bytes)(void *ctx);

    /*
     * destroy()
     *   Free everything init() allocated.
     *   Parameters : ctx - context returned by init()
     *   Return     : void
     */
    void   (*destroy)(void *ctx);
} AlgoOps;

/* ================================================================
 * Metrics -- raw counts and derived quality/cost figures.
 * Raw counters are filled by the run loop; derived fields by
 * metrics_finalize(). All algorithms get this for free.
 * ================================================================ */
typedef struct {
    /* ---- raw ---- */
    long rows;          /* total rows processed                              */
    long tp, fp, fn, tn;/* confusion-matrix counts                           */
    long n_events;      /* count of contiguous true-anomaly segments         */
    long events_caught; /* segments with at least one detection              */
    long delay_sum;     /* sum of rows-to-first-detection over caught events */
    double update_ns;   /* total time inside update() (nanoseconds)          */
    size_t model_bytes; /* model footprint reported by the algo              */

    /* ---- derived (filled by metrics_finalize) ---- */
    double precision, recall, f1;
    double specificity, fpr;      /* TN-rate and false-positive rate          */
    double balanced_acc, mcc;     /* imbalance-robust quality measures        */
    double mean_delay;            /* mean rows-to-detect over caught events   */
    double ns_per_update;         /* mean latency per update                  */
    double rows_per_sec;          /* throughput                               */
} Metrics;

/* ================================================================
 * Shared helpers implemented in framework.c
 * ================================================================ */

/*
 * param_get()
 *   Look up a parameter by key. Returns its value if present AND finite,
 *   otherwise the supplied default. This is the single place that enforces
 *   the "use the argument if valid, else fall back to the macro" rule.
 *   Parameters : p    - parsed parameter list (may be NULL)
 *                key  - parameter name to look up
 *                dflt - default value (an algorithm's *_DEFAULT_* macro)
 *   Return     : valid argument value, else dflt
 */
double param_get(const ParamList *p, const char *key, double dflt);

/*
 * composite_mean()
 *   Collapse a feature vector to a single scalar (arithmetic mean). Shared by
 *   1-D detectors (CUSUM, ADWIN, EWMA, ...) that act on one composite signal.
 *   Parameters : x          - feature vector
 *                n_features - number of valid entries in x
 *   Return     : mean of x[0 .. n_features-1], or 0.0 if n_features <= 0
 */
float composite_mean(const float *x, int n_features);

/*
 * framework_run()
 *   Stream the CSV, normalize features, drive one algorithm row by row, and
 *   fill a Metrics struct. Allocates nothing the caller must free.
 *   Parameters : cfg - parsed run configuration
 *                ops - the selected algorithm's vtable
 *                out - Metrics struct to populate
 *   Return     : 0 on success, non-zero on error (e.g. file not found)
 */
int framework_run(const Config *cfg, const AlgoOps *ops, Metrics *out);

/* ================================================================
 * Registry (registry.c) -- find an algorithm by name / enumerate all.
 * ================================================================ */
const AlgoOps *registry_find(const char *name);
const AlgoOps *registry_at(int idx);   /* returns NULL past the last entry */

#endif /* MAIN_H */
