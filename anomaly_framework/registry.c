/*
 * registry.c -- Algorithm Registry
 *
 * Description:
 * -----------
 *   Central table mapping an algorithm name (the -a argument) to its AlgoOps
 *   vtable. THIS IS THE ONLY FILE A TEAMMATE EDITS TO ADD AN ALGORITHM:
 *     1. add an `extern const AlgoOps <name>_ops;` declaration, and
 *     2. add `&<name>_ops,` to the REGISTRY array.
 *
 * Parameters:
 * -----------
 *   none
 *
 * Author:
 * --------
 *   Aanya Jain
 */
#include <string.h>

#include "main.h"

/* ---- Each algorithm exports one vtable; declare them here. ---- */
extern const AlgoOps cusum_ops;
extern const AlgoOps adwin_ops;
/* extern const AlgoOps iforest_ops;   <- teammates add their line here */

/* ---- Registry table (NULL-terminated). ---- */
static const AlgoOps *const REGISTRY[] = {
    &cusum_ops,
    &adwin_ops,
    /* &iforest_ops, */
    NULL
};

/*
 * registry_find()
 *   Locate an algorithm vtable by name (case-sensitive match on ops->name).
 *   Parameters : name - selector string from the -a argument
 *   Return     : pointer to the matching AlgoOps, or NULL if not found
 */
const AlgoOps *registry_find(const char *name)
{
    if (!name)
        return NULL;

    for (int i = 0; REGISTRY[i] != NULL; i++)
        if (strcmp(REGISTRY[i]->name, name) == 0)
            return REGISTRY[i];

    return NULL;
}

/*
 * registry_at()
 *   Enumerate registered algorithms by index (used for "-a all" and listing).
 *   Parameters : idx - zero-based position in the registry
 *   Return     : pointer to the AlgoOps at idx, or NULL past the last entry
 */
const AlgoOps *registry_at(int idx)
{
    int count = 0;
    while (REGISTRY[count] != NULL)
        count++;

    if (idx < 0 || idx >= count)
        return NULL;

    return REGISTRY[idx];
}
