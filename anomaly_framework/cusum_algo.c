/*
 * cusum_algo.c -- CUSUM plugin: implementation behind the AlgoOps vtable
 *
 * Description:
 * -----------
 *   Implements the five vtable entry points (init/update/score/model_bytes/
 *   destroy) for the CUSUM change-point detector. Contains ONLY the
 *   algorithm math; all CSV parsing, normalization and metrics live in the
 *   shared framework (framework.c).
 *
 * Parameters:
 * -----------
 *   See cusum.h for the tunable parameters (threshold, drift) and defaults.
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#include <stdlib.h>     /* calloc, free          */
#include <math.h>       /* sqrt                  */

#include "cusum.h"

/*
 * cusum_init()
 *   Allocate a CUSUM context and load parameters: a passed -p value is used
 *   when valid, otherwise the per-mode default macro.
 *   Parameters : n_features - unused (CUSUM collapses the vector internally)
 *                params     - parsed -p list
 *                mode       - selects the flow/ts default profile
 *   Return     : pointer to a zeroed, configured CUSUM, or NULL on failure
 */
static void *cusum_init(int n_features, const ParamList *params, RunMode mode)
{
    (void)n_features;   /* CUSUM works on a single composite scalar */

    /* Pick the default profile for this run mode. */
    double def_thr = (mode == MODE_FLOW) ? CUSUM_FLOW_DEFAULT_THRESHOLD
                                         : CUSUM_TS_DEFAULT_THRESHOLD;
    double def_drift = (mode == MODE_FLOW) ? CUSUM_FLOW_DEFAULT_DRIFT
                                           : CUSUM_TS_DEFAULT_DRIFT;

    CUSUM *c = (CUSUM *)calloc(1, sizeof(CUSUM));
    if (!c)
        return NULL;

    /* Use argument value if supplied & valid, else the default macro. */
    c->threshold = param_get(params, "threshold", def_thr);
    c->drift     = param_get(params, "drift",     def_drift);
    return c;
}

/*
 * cusum_update()
 *   Feed one normalized feature vector and return the anomaly decision.
 *   Parameters : ctx        - CUSUM context from cusum_init()
 *                x          - normalized feature vector
 *                n_features - number of valid entries in x
 *   Return     : 1 if anomaly detected, 0 otherwise
 */
static int cusum_update(void *ctx, const float *x, int n_features)
{
    CUSUM *c = (CUSUM *)ctx;

    /* Collapse the feature vector to a single composite signal. */
    double s = composite_mean(x, n_features);

    c->n++;

    /* Welford update of the running mean and variance accumulator. */
    double delta = s - c->mu;
    c->mu += delta / c->n;
    c->M2 += delta * (s - c->mu);

    /* Suppress detection until enough samples have been seen. */
    if (c->n < CUSUM_WARMUP_SAMPLES)
        return 0;

    /* Current standard deviation, then the z-score of this sample. */
    double sigma = sqrt(c->M2 / c->n);
    double z = (s - c->mu) / (sigma + EPSILON);

    /* Slowly adapt the mean so gradual drift is tracked, not alarmed on. */
    c->mu = (1.0 - CUSUM_EMA_ALPHA) * c->mu + CUSUM_EMA_ALPHA * s;

    /* Accumulate upward-shift evidence (clamped at zero). */
    c->pos_sum += z - c->drift;
    if (c->pos_sum < 0.0)
        c->pos_sum = 0.0;

    /* Accumulate downward-shift evidence (clamped at zero). */
    c->neg_sum += -z - c->drift;
    if (c->neg_sum < 0.0)
        c->neg_sum = 0.0;

    /* Alarm if either cumulative sum exceeds the threshold. */
    if (c->pos_sum > c->threshold || c->neg_sum > c->threshold) {
        /* Soft reset so the detector can re-trigger on later shifts. */
        c->pos_sum *= CUSUM_SOFT_RESET;
        c->neg_sum *= CUSUM_SOFT_RESET;
        return 1;
    }

    return 0;
}

/*
 * cusum_score()
 *   Return the anomaly score of the last update (the larger cumulative sum).
 *   Parameters : ctx - CUSUM context
 *   Return     : max(pos_sum, neg_sum) as a float
 */
static float cusum_score(void *ctx)
{
    CUSUM *c = (CUSUM *)ctx;
    return (float)(c->pos_sum > c->neg_sum ? c->pos_sum : c->neg_sum);
}

/*
 * cusum_model_bytes()
 *   Report the model's memory footprint (CUSUM is O(1) in input size).
 *   Parameters : ctx - CUSUM context (unused beyond sizing)
 *   Return     : sizeof(CUSUM)
 */
static size_t cusum_model_bytes(void *ctx)
{
    (void)ctx;
    return sizeof(CUSUM);
}

/*
 * cusum_destroy()
 *   Free the context allocated by cusum_init().
 *   Parameters : ctx - CUSUM context
 *   Return     : void
 */
static void cusum_destroy(void *ctx)
{
    free(ctx);
}

/* Exported vtable -- referenced by registry.c */
const AlgoOps cusum_ops = {
    "cusum",
    cusum_init,
    cusum_update,
    cusum_score,
    cusum_model_bytes,
    cusum_destroy
};
