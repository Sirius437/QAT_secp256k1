#include "cpa.h"
#include "cpa_cy_ln.h"
#include "cpa_sample_utils.h"
#include "cpa_eddsa_sample.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

extern CpaInstanceHandle cyInstHandle;

/* Big number modular operations */
CpaStatus bigNumMod(CpaFlatBuffer *r, CpaFlatBuffer *a, CpaFlatBuffer *m)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyLnModExpOpData *pOpData = NULL;
    Cpa8U expData = 1;  /* Store the exponent value */

    /* Allocate memory for operation data */
    status = OS_MALLOC(&pOpData, sizeof(CpaCyLnModExpOpData));
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set up the operation data */
        pOpData->base = *a;
        pOpData->exponent.dataLenInBytes = 1;
        pOpData->exponent.pData = &expData;  /* Use address of local variable */
        pOpData->modulus = *m;

        /* Perform modular operation */
        status = cpaCyLnModExp(cyInstHandle,
                            NULL, /* callback */
                            NULL, /* callback tag */
                            pOpData,
                            r);

        OS_FREE(pOpData);
    }

    return status;
}

CpaStatus bigNumModInv(CpaFlatBuffer *r, CpaFlatBuffer *a, CpaFlatBuffer *m)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyLnModExpOpData *pOpData = NULL;
    CpaFlatBuffer exp = {0};
    Cpa8U expData[DATA_LEN] = {0};

    /* Allocate memory for exponent */
    exp.pData = expData;
    exp.dataLenInBytes = DATA_LEN;

    /* Copy m-2 to exponent */
    memcpy(exp.pData, m->pData, m->dataLenInBytes);
    exp.pData[DATA_LEN-1] -= 2;  /* Safe subtraction on copy */

    /* Allocate memory for operation data */
    status = OS_MALLOC(&pOpData, sizeof(CpaCyLnModExpOpData));
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set up the operation data */
        pOpData->base = *a;
        pOpData->exponent = exp;  /* Use our local copy */
        pOpData->modulus = *m;

        /* Perform modular exponentiation */
        status = cpaCyLnModExp(cyInstHandle,
                            NULL, /* callback */
                            NULL, /* callback tag */
                            pOpData,
                            r);

        OS_FREE(pOpData);
    }

    return status;
}

CpaStatus bigNumModAdd(CpaFlatBuffer *r, CpaFlatBuffer *a, CpaFlatBuffer *b, CpaFlatBuffer *m)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U carry = 0;
    Cpa32U i;

    /* Check parameters */
    if (!r || !a || !b || !m || 
        !r->pData || !a->pData || !b->pData || !m->pData ||
        r->dataLenInBytes != DATA_LEN || 
        a->dataLenInBytes != DATA_LEN ||
        b->dataLenInBytes != DATA_LEN || 
        m->dataLenInBytes != DATA_LEN)
    {
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Perform addition */
    for (i = 0; i < DATA_LEN; i++)
    {
        Cpa32U idx = DATA_LEN - 1 - i;  /* Process from least significant byte */
        Cpa32U sum = a->pData[idx] + b->pData[idx] + carry;
        r->pData[idx] = sum & 0xFF;
        carry = sum >> 8;
    }

    /* If result >= m, subtract m */
    Cpa32U greater = 0;
    for (i = 0; i < DATA_LEN; i++)
    {
        if (r->pData[i] > m->pData[i])
        {
            greater = 1;
            break;
        }
        if (r->pData[i] < m->pData[i])
            break;
    }

    if (greater)
    {
        carry = 0;
        for (i = 0; i < DATA_LEN; i++)
        {
            Cpa32U idx = DATA_LEN - 1 - i;
            Cpa32U diff = r->pData[idx] - m->pData[idx] - carry;
            r->pData[idx] = diff & 0xFF;
            carry = (diff >> 8) & 1;
        }
    }

    return status;
}

CpaStatus bigNumModMul(CpaFlatBuffer *r, CpaFlatBuffer *a, CpaFlatBuffer *b, CpaFlatBuffer *m)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyLnModExpOpData *pOpData = NULL;

    /* Allocate memory for operation data */
    status = OS_MALLOC(&pOpData, sizeof(CpaCyLnModExpOpData));
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Set up the operation data */
        pOpData->base = *a;
        pOpData->exponent = *b;
        pOpData->modulus = *m;

        /* Perform modular multiplication using exponentiation */
        status = cpaCyLnModExp(cyInstHandle,
                            NULL, /* callback */
                            NULL, /* callback tag */
                            pOpData,
                            r);

        OS_FREE(pOpData);
    }

    return status;
}

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
