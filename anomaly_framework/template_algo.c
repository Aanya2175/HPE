/*
 * template_algo.c -- Skeleton implementation for a new algorithm plugin
 *
 * Description:
 * -----------
 *   Copy to <yourname>_algo.c and implement the five vtable functions. You
 *   write ONLY the math: CSV parsing, normalization and metrics are already
 *   handled by the framework. Each update() receives a normalized feature
 *   vector; collapse it with composite_mean() if your detector is 1-D.
 *
 * Parameters:
 * -----------
 *   See template.h for tunable parameters and defaults.
 *
 * Author:
 * --------
 *   <Your Name>
 */
#include <stdlib.h>     /* calloc, free */

#include "template.h"

/*
 * template_init()
 *   Allocate and configure context; read params with the "arg-or-default" rule.
 *   Parameters : n_features - features per update (use if you need the vector)
 *                params     - parsed -p list
 *                mode       - MODE_FLOW / MODE_TS (selects default profile)
 *   Return     : context pointer, or NULL on failure
 */
static void *template_init(int n_features, const ParamList *params, RunMode mode)
{
    (void)n_features;

    double def = (mode == MODE_FLOW) ? TEMPLATE_FLOW_DEFAULT_PARAM
                                     : TEMPLATE_TS_DEFAULT_PARAM;

    TEMPLATE *t = (TEMPLATE *)calloc(1, sizeof(TEMPLATE));
    if (!t)
        return NULL;

    t->param = param_get(params, "param", def);   /* arg if valid, else macro */
    return t;
}

/*
 * template_update()
 *   Feed one normalized feature vector; return 1 (anomaly) or 0 (normal).
 *   Parameters : ctx        - context from template_init()
 *                x          - normalized feature vector
 *                n_features - number of valid entries in x
 *   Return     : 1 if anomaly, 0 otherwise
 */
static int template_update(void *ctx, const float *x, int n_features)
{
    TEMPLATE *t = (TEMPLATE *)ctx;
    double s = composite_mean(x, n_features);   /* collapse to 1-D if needed */

    /* TODO: your detection logic. Set t->last_score for ROC/PR support. */
    t->last_score = s;
    return 0;
}

/*
 * template_score()
 *   Return the anomaly score of the last update (higher = more anomalous).
 *   Parameters : ctx - context
 *   Return     : last score
 */
static float template_score(void *ctx)
{
    return (float)((TEMPLATE *)ctx)->last_score;
}

/*
 * template_model_bytes()
 *   Report the model's memory footprint.
 *   Parameters : ctx - context
 *   Return     : bytes held by the model
 */
static size_t template_model_bytes(void *ctx)
{
    (void)ctx;
    return sizeof(TEMPLATE);
}

/*
 * template_destroy()
 *   Free everything template_init() allocated.
 *   Parameters : ctx - context
 *   Return     : void
 */
static void template_destroy(void *ctx)
{
    free(ctx);
}

/* Exported vtable -- add `extern const AlgoOps template_ops;` + a slot in registry.c */
const AlgoOps template_ops = {
    "template",
    template_init,
    template_update,
    template_score,
    template_model_bytes,
    template_destroy
};
