/*
 * template.h -- Skeleton header for a new algorithm plugin
 *
 * Description:
 * -----------
 *   Copy this file to <yourname>.h, replace TEMPLATE/Template/template with
 *   your algorithm's name, and fill in your state struct and default macros.
 *
 * Parameters (tunable via -p ...):
 * -----------
 *   <list each tunable parameter and what it does>
 *
 * Author:
 * --------
 *   <Your Name>
 */
#ifndef TEMPLATE_H
#define TEMPLATE_H

#include "main.h"

/* ---- Tunable defaults: one value per RunMode. Same logic, different tuning. */
#define TEMPLATE_FLOW_DEFAULT_PARAM  1.0
#define TEMPLATE_TS_DEFAULT_PARAM    1.0

/* ---- Fixed algorithm constants (never leave a bare number in the .c). ---- */
/* #define TEMPLATE_SOME_CONSTANT  42 */

/* ---- Your detector's state. Define it HERE, not in the .c file. ---- */
typedef struct {
    double param;     /* example tunable parameter                          */
    double last_score;/* score of the most recent update (for score())      */
    /* ... your running state ... */
} TEMPLATE;

extern const AlgoOps template_ops;   /* register this in registry.c */

#endif /* TEMPLATE_H */
