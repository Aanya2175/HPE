/*
 * cusum.h -- CUSUM (Cumulative Sum) Change-Point Detector: types & defaults
 *
 * Description:
 * -----------
 *   Per-algorithm header for the CUSUM plugin. Holds the detector's state
 *   struct, its tunable-parameter default macros (one profile per RunMode),
 *   and the exported vtable. Includes the shared contract from main.h.
 *
 *   CUSUM accumulates standardized deviations of a running signal and raises
 *   an alarm when either the upward or downward cumulative sum crosses a
 *   threshold. Logic is identical for flow and time-series data; only the
 *   default threshold/drift differ.
 *
 * Parameters (tunable via -p threshold=..,drift=..):
 * -----------
 *   threshold - alarm level; higher  -> fewer false positives
 *   drift     - slack/allowance; higher -> less sensitive to small shifts
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#ifndef CUSUM_H
#define CUSUM_H

#include "main.h"

/* ================================================================
 * Tunable defaults (used when -p does not supply a valid value)
 * ================================================================ */
#define CUSUM_FLOW_DEFAULT_THRESHOLD  5.5    /* alarm level, flow profile     */
#define CUSUM_FLOW_DEFAULT_DRIFT      0.08   /* slack, flow profile           */
#define CUSUM_TS_DEFAULT_THRESHOLD    5.0    /* alarm level, ts profile       */
#define CUSUM_TS_DEFAULT_DRIFT        0.05   /* slack, ts profile             */

/* ================================================================
 * Fixed algorithm constants (formerly hard-coded magic numbers)
 * ================================================================ */
#define CUSUM_WARMUP_SAMPLES   30      /* rows seen before detection starts   */
#define CUSUM_EMA_ALPHA        0.005   /* weight of new sample in mean EMA     */
#define CUSUM_SOFT_RESET       0.5     /* cumulative sums *= this after alarm  */

/* ================================================================
 * CUSUM detector state.
 * (Removed from the original: 'sigma' was recomputed locally every call,
 *  and 'ready' was never used -- both deleted.)
 * ================================================================ */
typedef struct {
    double threshold;   /* alarm threshold for the cumulative sums           */
    double drift;       /* allowable slack before accumulation begins        */
    double pos_sum;     /* cumulative sum of positive (upward) deviations     */
    double neg_sum;     /* cumulative sum of negative (downward) deviations   */
    double mu;          /* running mean of the composite signal              */
    double M2;          /* Welford variance accumulator for the signal       */
    long   n;           /* number of samples processed so far                */
} CUSUM;

extern const AlgoOps cusum_ops;   /* registered in registry.c */

#endif /* CUSUM_H */
