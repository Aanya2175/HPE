/*
 * adwin_algo.c -- ADWIN plugin: implementation behind the AlgoOps vtable
 *
 * Description:
 * -----------
 *   Implements the five vtable entry points (init/update/score/model_bytes/
 *   destroy) for the ADWIN change detector. Contains ONLY the algorithm math;
 *   all CSV parsing, normalization and metrics live in the shared framework.
 *
 * Parameters:
 * -----------
 *   See adwin.h for the tunable parameter (delta) and defaults.
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#include <stdlib.h>     /* calloc, free          */
#include <math.h>       /* sqrt, log, fabs       */

#include "adwin.h"

/*
 * adwin_get_at()
 *   Read the i-th oldest sample from the ring buffer.
 *   Parameters : a   - ADWIN context
 *                idx - logical offset from the oldest sample (0-based)
 *   Return     : the stored sample value
 */
static double adwin_get_at(const ADWIN *a, int idx)
{
    return a->window[(a->head + idx) % ADWIN_MAX_WINDOW];
}

/*
 * adwin_init()
 *   Allocate an ADWIN context and load the confidence parameter: a passed -p
 *   value is used when valid, otherwise the per-mode default macro.
 *   Parameters : n_features - unused (ADWIN works on a single composite)
 *                params     - parsed -p list
 *                mode       - selects the flow/ts default profile
 *   Return     : pointer to a zeroed, configured ADWIN, or NULL on failure
 */
static void *adwin_init(int n_features, const ParamList *params, RunMode mode)
{
    (void)n_features;   /* ADWIN works on a single composite scalar */

    double def_delta = (mode == MODE_FLOW) ? ADWIN_FLOW_DEFAULT_DELTA
                                           : ADWIN_TS_DEFAULT_DELTA;

    ADWIN *a = (ADWIN *)calloc(1, sizeof(ADWIN));
    if (!a)
        return NULL;

    /* Use argument value if supplied & valid, else the default macro. */
    a->delta = param_get(params, "delta", def_delta);
    return a;
}

/*
 * adwin_update()
 *   Feed one normalized feature vector and return the anomaly decision.
 *   Parameters : ctx        - ADWIN context from adwin_init()
 *                x          - normalized feature vector
 *                n_features - number of valid entries in x
 *   Return     : 1 if a change (anomaly) is detected, 0 otherwise
 */
static int adwin_update(void *ctx, const float *x, int n_features)
{
    ADWIN *a = (ADWIN *)ctx;

    /* Collapse the feature vector to a single composite signal. */
    double s = composite_mean(x, n_features);

    a->total_n++;
    a->last_score = 0.0;

    /* Append to the ring buffer; once full, overwrite the oldest sample. */
    if (a->size < ADWIN_MAX_WINDOW) {
        int pos = (a->head + a->size) % ADWIN_MAX_WINDOW;
        a->window[pos] = s;
        a->size++;
    } else {
        a->window[a->head] = s;
        a->head = (a->head + 1) % ADWIN_MAX_WINDOW;
    }

    /* Need a minimum amount of history before testing for change. */
    if (a->size < ADWIN_MIN_WINDOW)
        return 0;

    /* Sum of the whole window (used to derive the right sub-window mean). */
    double total_sum = 0.0;
    for (int i = 0; i < a->size; i++)
        total_sum += adwin_get_at(a, i);

    /*
     * Try geometrically growing split points k. For each split, compare the
     * mean of the left sub-window (n0 samples) against the right (n1).
     * 'prefix' accumulates the left-side sum incrementally across splits.
     * NOTE: this incremental accumulation mirrors the original tuned code;
     * if you ever re-validate against canonical ADWIN, check the prefix
     * covers indices [0, k) exactly. Behaviour is intentionally unchanged.
     */
    double prefix = 0.0;
    for (int k = ADWIN_MIN_SUBWINDOW;
         k < a->size - ADWIN_MIN_SUBWINDOW;
         k *= ADWIN_SPLIT_GROWTH) {

        for (int i = k / 2; i < k; i++)
            prefix += adwin_get_at(a, i);

        int n0 = k;
        int n1 = a->size - k;

        double mu0 = prefix / n0;
        double mu1 = (total_sum - prefix) / n1;

        /* Harmonic-style size term used by the Hoeffding bound. */
        double m = (double)(n0 * n1) / (n0 + n1);

        /* Confidence bound: shrinks as the window grows / delta loosens. */
        double eps = sqrt((1.0 / (2.0 * m)) *
                          log(ADWIN_CONFIDENCE_NUM * a->total_n / a->delta));

        /* Track the strongest evidence as a threshold-free score. */
        double ratio = fabs(mu0 - mu1) / (eps + EPSILON);
        if (ratio > a->last_score)
            a->last_score = ratio;

        if (fabs(mu0 - mu1) > eps)
            return 1;
    }

    return 0;
}

/*
 * adwin_score()
 *   Return the anomaly score of the last update (strongest split evidence).
 *   Parameters : ctx - ADWIN context
 *   Return     : max over split points of |mu0 - mu1| / eps
 */
static float adwin_score(void *ctx)
{
    ADWIN *a = (ADWIN *)ctx;
    return (float)a->last_score;
}

/*
 * adwin_model_bytes()
 *   Report the model's memory footprint (bounded by the fixed ring buffer).
 *   Parameters : ctx - ADWIN context (unused beyond sizing)
 *   Return     : sizeof(ADWIN)
 */
static size_t adwin_model_bytes(void *ctx)
{
    (void)ctx;
    return sizeof(ADWIN);
}

/*
 * adwin_destroy()
 *   Free the context allocated by adwin_init().
 *   Parameters : ctx - ADWIN context
 *   Return     : void
 */
static void adwin_destroy(void *ctx)
{
    free(ctx);
}

/* Exported vtable -- referenced by registry.c */
const AlgoOps adwin_ops = {
    "adwin",
    adwin_init,
    adwin_update,
    adwin_score,
    adwin_model_bytes,
    adwin_destroy
};
