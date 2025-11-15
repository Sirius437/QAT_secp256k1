/***************************************************************************
 *
 *
 *   BSD LICENSE
 * 
 *   Copyright(c) 2007-2024 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 *  version: QAT.L.4.27.0-00006
 *
 *
 ***************************************************************************/

/***************************************************************************
 * @file cpa_ed_point_operations.c
 *
 * @description
 *     This file contains functions used in point operations on secp256k1
 *     curve. All integers are stored in big-endian format.
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cpa.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_ln.h"
#include "cpa_cy_common.h"
#include "icp_sal_poll.h"  /* For icp_sal_CyPollInstance */
#include "cpa_sample_utils.h"
#include "cpa_eddsa_sample.h"
#include "cpa_ed_point_operations.h"
#include <pthread.h>

#if CY_API_VERSION_AT_LEAST(2, 3)

extern int gDebugParam;
extern CpaInstanceHandle cyInstHandle;

#define NUM_SPARE_INSTANCES 2
static CpaInstanceHandle gSpareInstances[NUM_SPARE_INSTANCES];
static CpaBoolean gSpareInstancesInitialized = CPA_FALSE;
static pthread_mutex_t gSpareInitMutex = PTHREAD_MUTEX_INITIALIZER;

/* Initialize spare instances */
static CpaStatus initSpareInstances(void)
{
    CpaStatus status;
    
    /* Quick check without lock first */
    if (gSpareInstancesInitialized)
        return CPA_STATUS_SUCCESS;

    /* Use mutex to ensure thread-safe initialization */
    pthread_mutex_lock(&gSpareInitMutex);
    
    /* Check again after acquiring lock */
    if (gSpareInstancesInitialized) {
        pthread_mutex_unlock(&gSpareInitMutex);
        return CPA_STATUS_SUCCESS;
    }

    Cpa16U numInstances = 0;
    CpaInstanceHandle *handles = NULL;

    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status || numInstances < NUM_SPARE_INSTANCES + 1)
    {
        PRINT_ERR("Not enough instances for spare pool (need %d, have %d)\n",
                  NUM_SPARE_INSTANCES + 1, numInstances);
        pthread_mutex_unlock(&gSpareInitMutex);
        return CPA_STATUS_FAIL;
    }

    handles = malloc(sizeof(CpaInstanceHandle) * numInstances);
    if (!handles) {
        pthread_mutex_unlock(&gSpareInitMutex);
        return CPA_STATUS_RESOURCE;
    }

    status = cpaCyGetInstances(numInstances, handles);
    if (CPA_STATUS_SUCCESS == status)
    {
        /* Reserve last NUM_SPARE_INSTANCES instances for spare pool */
        for (Cpa16U i = 0; i < NUM_SPARE_INSTANCES; i++)
        {
            gSpareInstances[i] = handles[numInstances - 1 - i];
            status = cpaCySetAddressTranslation(gSpareInstances[i], sampleVirtToPhys);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to set address translation for spare instance %d\n", i);
                free(handles);
                pthread_mutex_unlock(&gSpareInitMutex);
                return status;
            }
            status = cpaCyStartInstance(gSpareInstances[i]);
            if (CPA_STATUS_SUCCESS != status)
            {
                PRINT_ERR("Failed to start spare instance %d\n", i);
                free(handles);
                pthread_mutex_unlock(&gSpareInitMutex);
                return status;
            }
            PRINT_DBG("initSpareInstances(): Initialized spare instance %d successfully\n", i);
        }
        PRINT_DBG("initSpareInstances(): Successfully initialized %d spare instances\n", 
                  NUM_SPARE_INSTANCES);
        gSpareInstancesInitialized = CPA_TRUE;
    }

    free(handles);
    pthread_mutex_unlock(&gSpareInitMutex);
    return status;
}

/* Structure to track retry state */
typedef struct {
    CpaInstanceHandle lastInstance;
    CpaBoolean usingSpare;
    CpaStatus lastStatus;
    Cpa32U currentSpareIndex;
    CpaBoolean switchedToSpare;  /* Track if we've logged the switch */
    pthread_t threadId;          /* System thread ID */
    Cpa32U threadNum;           /* Simple sequential thread number */
} RetryState;

#define MAX_PARALLEL_THREADS 384  /* Match max instances */
static RetryState gRetryStates[MAX_PARALLEL_THREADS] = {0};
static Cpa32U gRetryStateCount = 0;
static pthread_mutex_t gRetryStateLock = PTHREAD_MUTEX_INITIALIZER;
static Cpa32U gNextThreadNum = 0;  /* For assigning sequential thread numbers */

/* Get retry state for current thread */
static RetryState* getThreadRetryState(void)
{
    pthread_t currentThread = pthread_self();
    RetryState* state = NULL;
    
    pthread_mutex_lock(&gRetryStateLock);
    
    /* Look for existing state */
    for (Cpa32U i = 0; i < gRetryStateCount; i++)
    {
        if (pthread_equal(gRetryStates[i].threadId, currentThread))
        {
            state = &gRetryStates[i];
            break;
        }
    }
    
    /* Create new state if needed */
    if (!state && gRetryStateCount < MAX_PARALLEL_THREADS)
    {
        state = &gRetryStates[gRetryStateCount++];
        state->threadId = currentThread;
        state->threadNum = ++gNextThreadNum;
        state->usingSpare = CPA_FALSE;
        state->switchedToSpare = CPA_FALSE;
        state->currentSpareIndex = 0;
    }
    
    pthread_mutex_unlock(&gRetryStateLock);
    return state;
}

/* Structure to track retry statistics */
typedef struct {
    volatile Cpa32U totalRetries;
    volatile Cpa32U maxRetriesPerOp;
    volatile Cpa32U opsWithRetries;
    volatile Cpa32U totalOps;
    struct timespec startTime;
    volatile Cpa32U retryDistribution[3];  /* Count of ops with 1, 2, or 3 retries */
    volatile CpaBoolean initialized;
    volatile Cpa32U activeThreads;  /* Count of active threads */
} RetryStats;

static RetryStats gRetryStats = {0};
static pthread_mutex_t gStatsLock = PTHREAD_MUTEX_INITIALIZER;

/* One-time initialization function */
static void initStatsOnce(void)
{
    memset(&gRetryStats, 0, sizeof(RetryStats));
    clock_gettime(CLOCK_MONOTONIC, &gRetryStats.startTime);
    gRetryStats.initialized = CPA_TRUE;
    PRINT_DBG("Initialized retry statistics tracking\n");
}

/* Initialize retry statistics - called once at the start */
static void initRetryStats(void)
{
    static pthread_once_t initOnce = PTHREAD_ONCE_INIT;
    pthread_once(&initOnce, initStatsOnce);
}

/* Update retry statistics */
static void updateRetryStats(Cpa32U retryCount)
{
    initRetryStats();  /* Safe to call multiple times due to pthread_once */

    pthread_mutex_lock(&gStatsLock);
    if (retryCount > 0) {
        gRetryStats.opsWithRetries++;
        gRetryStats.totalRetries += retryCount;
        if (retryCount > gRetryStats.maxRetriesPerOp) {
            gRetryStats.maxRetriesPerOp = retryCount;
        }
        if (retryCount <= 3) {
            gRetryStats.retryDistribution[retryCount - 1]++;
        }
    }
    gRetryStats.totalOps++;
    pthread_mutex_unlock(&gStatsLock);
}

/* Print retry statistics */
void printRetryStats(double elapsedTime)
{
    if (!gRetryStats.initialized) {
        PRINT_DBG("Statistics not yet initialized\n");
        return;
    }

    pthread_mutex_lock(&gStatsLock);
    
    /* Calculate time-based metrics */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (double)(now.tv_sec - gRetryStats.startTime.tv_sec) +
                    (double)(now.tv_nsec - gRetryStats.startTime.tv_nsec) / 1.0e9;
    
    if (elapsed < 0.001) elapsed = 0.001;  /* Avoid division by zero */
    
    double opsPerSec = (double)gRetryStats.totalOps / elapsed;
    float retryRate = (gRetryStats.totalOps > 0) ? 
        ((float)gRetryStats.opsWithRetries / gRetryStats.totalOps) * 100.0 : 0;
    float avgRetries = (gRetryStats.opsWithRetries > 0) ?
        ((float)gRetryStats.totalRetries / gRetryStats.opsWithRetries) : 0;
    
    PRINT_DBG("\nRetry Statistics:\n");
    PRINT_DBG("- Operations processed: %u (%.1f ops/sec)\n", 
              gRetryStats.totalOps, opsPerSec);
    
    if (gRetryStats.opsWithRetries > 0) {
        PRINT_DBG("- Operations with retries: %u (%.1f%%)\n", 
                  gRetryStats.opsWithRetries, retryRate);
        PRINT_DBG("- Average retries when needed: %.1f\n", avgRetries);
        PRINT_DBG("- Maximum retries for any op: %u\n", 
                  gRetryStats.maxRetriesPerOp);
        
        if (gRetryStats.retryDistribution[0] > 0) {
            PRINT_DBG("\nRetry Distribution:\n");
            for (int i = 0; i < 3; i++) {
                if (gRetryStats.retryDistribution[i] > 0) {
                    float pct = ((float)gRetryStats.retryDistribution[i] / 
                                gRetryStats.opsWithRetries) * 100.0;
                    PRINT_DBG("- %d retry:  %u operations (%.1f%%)\n", 
                             i + 1, gRetryStats.retryDistribution[i], pct);
                }
            }
        }
    } else {
        PRINT_DBG("- No retries needed in this period\n");
    }
    
    pthread_mutex_unlock(&gStatsLock);
}

/* Get next instance for retry, tracking state */
static CpaInstanceHandle getRetryInstance(Cpa32U currentRetry)
{
    CpaInstanceHandle instance;
    RetryState* state = getThreadRetryState();
    static pthread_mutex_t logMutex = PTHREAD_MUTEX_INITIALIZER;
    static Cpa32U retryCount = 0;
    
    if (!state)
    {
        PRINT_ERR("Failed to get retry state for thread\n");
        return cyInstHandle;  /* Fallback to main instance */
    }

    /* First attempt always uses main instance */
    if (currentRetry == 0)
    {
        state->usingSpare = CPA_FALSE;
        state->lastInstance = cyInstHandle;
        state->currentSpareIndex = 0;
        state->switchedToSpare = CPA_FALSE;
        return cyInstHandle;
    }

    /* For retries, alternate between spare instances */
    instance = gSpareInstances[state->currentSpareIndex];
    state->currentSpareIndex = (state->currentSpareIndex + 1) % NUM_SPARE_INSTANCES;
    
    /* Only log the first switch to spare instance pool and limit frequency */
    if (!state->switchedToSpare)
    {
        pthread_mutex_lock(&logMutex);
        retryCount++;
        /* Log only every 100th retry to reduce noise */
        if (retryCount % 100 == 0)
        {
            PRINT_DBG("Retry milestone: %u total retries across all threads\n",
                     retryCount);
        }
        pthread_mutex_unlock(&logMutex);
        state->switchedToSpare = CPA_TRUE;
        state->usingSpare = CPA_TRUE;
    }

    state->lastInstance = instance;
    return instance;
}

/* Wait for completion function */
static CpaStatus waitForCompletion(volatile CpaBoolean *complete)
{
    Cpa32U retries = 0;
    const Cpa32U maxRetries = 100000; /* Increase timeout value */

    while (!(*complete) && retries < maxRetries)
    {
        icp_sal_CyPollInstance(cyInstHandle, 0);
        OS_SLEEP(10);
        retries++;
    }

    if (retries >= maxRetries)
    {
        PRINT_ERR("Operation timed out\n");
        return CPA_STATUS_FAIL;
    }

    return CPA_STATUS_SUCCESS;
}

/* Callback function for asynchronous operations */
static void operationComplete(void *pCallbackTag,
                            CpaStatus status,
                            void *pOpData,
                            CpaFlatBuffer *pOut)
{
    if (NULL != pCallbackTag)
    {
        if (CPA_STATUS_SUCCESS == status)
        {
            *(volatile CpaBoolean *)pCallbackTag = CPA_TRUE;
        }
        else
        {
            PRINT_ERR("Async operation failed with status: %d\n", status);
            *(volatile CpaBoolean *)pCallbackTag = CPA_TRUE; /* Set to true to unblock the wait */
        }
    }
}

/* Helper function to cleanup allocated resources */
static void cleanupResources(CpaCyEcPointMultiplyOpData *pOpData,
                           CpaFlatBuffer *pXData,
                           CpaFlatBuffer *pYData)
{
    if (pOpData)
    {
        if (pOpData->k.pData)
            PHYS_CONTIG_FREE(pOpData->k.pData);
        if (pOpData->xg.pData)
            PHYS_CONTIG_FREE(pOpData->xg.pData);
        if (pOpData->yg.pData)
            PHYS_CONTIG_FREE(pOpData->yg.pData);
        if (pOpData->a.pData)
            PHYS_CONTIG_FREE(pOpData->a.pData);
        if (pOpData->b.pData)
            PHYS_CONTIG_FREE(pOpData->b.pData);
        if (pOpData->q.pData)
            PHYS_CONTIG_FREE(pOpData->q.pData);
        if (pOpData->h.pData)
            PHYS_CONTIG_FREE(pOpData->h.pData);
        OS_FREE(pOpData);
    }
    if (pXData)
    {
        if (pXData->pData)
            PHYS_CONTIG_FREE(pXData->pData);
        OS_FREE(pXData);
    }
    if (pYData)
    {
        if (pYData->pData)
            PHYS_CONTIG_FREE(pYData->pData);
        OS_FREE(pYData);
    }
}

/* secp256k1 curve parameters */
static const Cpa8U prime[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F
};

/* Point multiplication using QAT hardware acceleration */
CpaStatus pointMultiplication(const Cpa8U *pPointX,
                          const Cpa8U *pPointY,
                          const Cpa8U *scalar,
                          Cpa8U *pResultX,
                          Cpa8U *pResultY)
{
    /* Initialize statistics if not done yet */
    if (!gRetryStats.initialized) {
        initRetryStats();
    }

    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyEcPointMultiplyOpData *pOpData = NULL;
    CpaFlatBuffer *pXData = NULL;
    CpaFlatBuffer *pYData = NULL;
    volatile CpaBoolean complete = CPA_FALSE;
    CpaBoolean *pComplete = (CpaBoolean *)&complete;
    Cpa32U currentRetry = 0;

    /* Initialize spare instances if not already done */
    if (!gSpareInstancesInitialized)
    {
        status = initSpareInstances();
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to initialize spare instances\n");
            return status;
        }
    }

    /* Parameter validation */
    if (!pPointX || !pPointY || !scalar || !pResultX || !pResultY)
    {
        PRINT_ERR("Invalid parameters\n");
        return CPA_STATUS_INVALID_PARAM;
    }

retry:
    /* Reset complete flag for retry */
    complete = CPA_FALSE;

    /* Get appropriate instance based on retry count */
    CpaInstanceHandle currentInstance = getRetryInstance(currentRetry);

    /* Allocate memory for operation data */
    status = OS_MALLOC(&pOpData, sizeof(CpaCyEcPointMultiplyOpData));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate operation data\n");
        return status;
    }

    /* Set up point multiplication parameters */
    pOpData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    pOpData->k.dataLenInBytes = 32;
    pOpData->xg.dataLenInBytes = 32;
    pOpData->yg.dataLenInBytes = 32;
    pOpData->a.dataLenInBytes = 32;
    pOpData->b.dataLenInBytes = 32;
    pOpData->q.dataLenInBytes = 32;
    pOpData->h.dataLenInBytes = 1;

    /* Allocate memory for the point coordinates and scalar */
    status = PHYS_CONTIG_ALLOC(&pOpData->k.pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate scalar data\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pOpData->xg.pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate X coordinate data\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pOpData->yg.pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate Y coordinate data\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pOpData->a.pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate curve parameter a\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pOpData->b.pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate curve parameter b\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pOpData->q.pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate prime modulus\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pOpData->h.pData, 1);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate cofactor\n");
        goto cleanup;
    }

    /* Copy input data */
    memcpy(pOpData->k.pData, scalar, 32);
    memcpy(pOpData->xg.pData, pPointX, 32);
    memcpy(pOpData->yg.pData, pPointY, 32);
    memcpy(pOpData->q.pData, prime, 32);

    /* Set curve parameters for secp256k1 */
    memset(pOpData->a.pData, 0, 32);  /* a = 0 */
    pOpData->b.pData[31] = 7;       /* b = 7 */
    pOpData->h.pData[0] = 1;                /* h = 1 (cofactor) */

    /* Allocate result buffers */
    status = OS_MALLOC(&pXData, sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate X result buffer\n");
        goto cleanup;
    }

    status = OS_MALLOC(&pYData, sizeof(CpaFlatBuffer));
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate Y result buffer\n");
        goto cleanup;
    }

    pXData->dataLenInBytes = 32;
    pYData->dataLenInBytes = 32;

    status = PHYS_CONTIG_ALLOC(&pXData->pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate X result data\n");
        goto cleanup;
    }

    status = PHYS_CONTIG_ALLOC(&pYData->pData, 32);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate Y result data\n");
        goto cleanup;
    }

    /* Perform point multiplication */
    status = cpaCyEcPointMultiply(currentInstance,
                                (CpaCyEcPointMultiplyCbFunc)operationComplete,
                                (void *)&complete,
                                pOpData,
                                pComplete,
                                pXData,
                                pYData);

    if (CPA_STATUS_SUCCESS == status)
    {
        /* Wait for completion */
        status = waitForCompletion(&complete);
    }

    if (status != CPA_STATUS_SUCCESS && currentRetry < 3)
    {
        currentRetry++;
        RetryState* state = getThreadRetryState();
        
        if (status == CPA_STATUS_RETRY && state)
        {
            /* Debug logging removed to reduce noise */
            if (currentRetry == 3)  /* Only log final retry */
            {
                PRINT_DBG("Thread %u max retries reached\n", state->threadNum);
            }
        }
        else if (status != CPA_STATUS_RETRY)
        {
            PRINT_DBG("Operation failed with status %d (retry %d)\n",
                     status, currentRetry);
        }

        /* Exponential backoff with jitter */
        Cpa32U base_sleep = 25 * (1 << (currentRetry - 1));
        Cpa32U jitter = rand() % (base_sleep / 2);
        OS_SLEEP(base_sleep + jitter);

        /* Clean up resources before retry */
        cleanupResources(pOpData, pXData, pYData);
        pOpData = NULL;
        pXData = NULL;
        pYData = NULL;

        goto retry;
    }

    /* Update retry statistics and reset thread state */
    updateRetryStats(currentRetry);
    RetryState* state = getThreadRetryState();
    if (state)
    {
        state->usingSpare = CPA_FALSE;
        state->currentSpareIndex = 0;
        state->switchedToSpare = CPA_FALSE;
    }

    /* Copy results if successful */
    if (CPA_STATUS_SUCCESS == status)
    {
        memcpy(pResultX, pXData->pData, 32);
        memcpy(pResultY, pYData->pData, 32);
    }
    else
    {
        PRINT_ERR("Point multiplication failed after %d retries. Final status: %d\n",
                  currentRetry, status);
    }

cleanup:
    /* Cleanup allocated resources */
    cleanupResources(pOpData, pXData, pYData);
    return status;
}

/* Encode a point in uncompressed SEC format */
void encodePoint(const Cpa8U *pPointX,
                const Cpa8U *pPointY,
                Cpa8U *encPoint)
{
    encPoint[0] = 0x04;  /* Uncompressed point format */
    memcpy(encPoint + 1, pPointX, 32);
    memcpy(encPoint + 33, pPointY, 32);
}

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
