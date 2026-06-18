/*
 * adwin.h -- ADWIN (ADaptive WINdowing) Change Detector: types & defaults
 *
 * Description:
 * -----------
 *   Per-algorithm header for the ADWIN plugin. Holds the detector's state
 *   struct, its tunable-parameter default macros (one profile per RunMode),
 *   and the exported vtable. Includes the shared contract from main.h.
 *
 *   ADWIN keeps a sliding window of the recent composite signal and, at
 *   several split points, compares the means of the two sub-windows. A
 *   statistically significant difference (Hoeffding-style bound) signals a
 *   change. Logic is identical for flow and time-series data; only the
 *   default confidence delta differs.
 *
 * Parameters (tunable via -p delta=..):
 * -----------
 *   delta - confidence parameter; smaller -> stricter (fewer false alarms)
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#ifndef ADWIN_H
#define ADWIN_H

#include "main.h"

/* ================================================================
 * Tunable defaults (used when -p does not supply a valid value)
 * ================================================================ */
#define ADWIN_FLOW_DEFAULT_DELTA   0.002   /* confidence delta, flow profile  */
#define ADWIN_TS_DEFAULT_DELTA     0.001   /* confidence delta, ts profile    */

/* ================================================================
 * Fixed algorithm constants (formerly hard-coded magic numbers)
 * ================================================================ */
#define ADWIN_MAX_WINDOW      512    /* ring-buffer capacity (samples)        */
#define ADWIN_MIN_WINDOW       16    /* min samples before any split is tried */
#define ADWIN_MIN_SUBWINDOW     8    /* smallest sub-window at a split point   */
#define ADWIN_SPLIT_GROWTH      2    /* split point grows geometrically by x  */
#define ADWIN_CONFIDENCE_NUM  4.0    /* numerator in the Hoeffding bound term */

/* ================================================================
 * ADWIN detector state (fixed-size ring buffer -> bounded memory).
 * ================================================================ */
typedef struct {
    double window[ADWIN_MAX_WINDOW]; /* ring buffer of recent samples         */
    int    head;                     /* index of the oldest valid sample      */
    int    size;                     /* number of valid samples in the window */
    double delta;                    /* confidence parameter                  */
    long   total_n;                  /* total samples ever seen (bound term)  */
    double last_score;               /* score of the most recent update        */
} ADWIN;

extern const AlgoOps adwin_ops;   /* registered in registry.c */

#endif /* ADWIN_H */
