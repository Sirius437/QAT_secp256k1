#include "cpa.h"
#include "cpa_cy_nrbg.h"
#include "cpa_sample_utils.h"
#include "cpa_eddsa_sample.h"
#include <immintrin.h>  // For RDRAND intrinsic
#include <stdlib.h>
#include <time.h>

#if CY_API_VERSION_AT_LEAST(2, 3)

extern CpaInstanceHandle cyInstHandle;

CpaStatus copyToFlatBuffer(CpaFlatBuffer *dest, const Cpa8U *src, Cpa32U len)
{
    if (!dest || !src || !dest->pData)
        return CPA_STATUS_INVALID_PARAM;

    memcpy(dest->pData, src, len);
    dest->dataLenInBytes = len;
    return CPA_STATUS_SUCCESS;
}

CpaStatus memcpy_reverse(Cpa8U *dest, const Cpa8U *src, size_t len)
{
    if (!dest || !src)
        return CPA_STATUS_INVALID_PARAM;

    for (size_t i = 0; i < len; i++)
    {
        dest[i] = src[len - 1 - i];
    }
    return CPA_STATUS_SUCCESS;
}

CpaStatus generateRandomBytes(Cpa8U *buffer, Cpa32U length)
{
    static int seeded = 0;
    if (!seeded) {
        srand(time(NULL));
        seeded = 1;
    }

    for (Cpa32U i = 0; i < length; i++) {
        buffer[i] = (Cpa8U)(rand() & 0xFF);
    }

    return CPA_STATUS_SUCCESS;
}

CpaStatus hashMessage(const Cpa8U *message, Cpa32U messageLen, Cpa8U *hash)
{
    /* For testing purposes, just copy the first 32 bytes of the message */
    Cpa32U copyLen = (messageLen < 32) ? messageLen : 32;
    memcpy(hash, message, copyLen);
    if (copyLen < 32) {
        memset(hash + copyLen, 0, 32 - copyLen);
    }
    return CPA_STATUS_SUCCESS;
}

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
