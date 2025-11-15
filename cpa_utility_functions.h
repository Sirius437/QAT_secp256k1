#ifndef CPA_UTILITY_FUNCTIONS_H
#define CPA_UTILITY_FUNCTIONS_H

#include "cpa.h"
#include "cpa_cy_ln.h"

/* Utility functions */
CpaStatus copyToFlatBuffer(CpaFlatBuffer *dest, const Cpa8U *src, Cpa32U len);
CpaStatus bigNumMod(CpaFlatBuffer *r, CpaFlatBuffer *a, CpaFlatBuffer *m);
void encodePoint(const Cpa8U *pPointX, const Cpa8U *pPointY, Cpa8U *encPoint);

#endif /* CPA_UTILITY_FUNCTIONS_H */
