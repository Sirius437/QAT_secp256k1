/*** @file cpa_eddsa_sample.c
 *
 * @description
 *     This file contains functions that performs ECDSA operations on secp256k1 curve.
 *     Sample represents ECDSA operations on secp256k1 curve using Intel QAT
 *     hardware acceleration.
 *     
 *     Modified to generate Bitcoin private keys and check against high-value addresses.
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* For usleep() */
#include <pthread.h>
#include <getopt.h>  /* For command line parsing */
#include <signal.h>  /* For signal handling */
#include <stdint.h>  /* For intptr_t */
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_im.h"
#include "cpa_cy_rsa.h"
#include "cpa_sample_utils.h"
#include "cpa_ed_point_operations.h"
#include "icp_sal_user.h"  /* For icp_sal_userStart and icp_sal_userStop */
#include "cpa_cy_ln.h"
#include "cpa_cy_common.h"
#include "icp_sal_poll.h"
#include "cpa_eddsa_sample.h"
#include "cpa_utility_functions.h"
#include "time.h"
#include <math.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/types.h>

#if CY_API_VERSION_AT_LEAST(2, 3)

/* Global variables */
static CpaInstanceHandle *gInstances = NULL;
static Cpa16U gNumInstances = 0;  /* Changed to Cpa16U to match API */
static pthread_t *gThreads = NULL;
static pthread_t *gPollingThreads = NULL;
static volatile Cpa32U gIterationCount = 0;
static volatile Cpa32U gMatchCount = 0;
static volatile CpaBoolean gStopThreads = CPA_FALSE;
static volatile Cpa32U gCompletedThreads = 0;
static volatile Cpa64U gTotalKeysGenerated = 0;  /* Counter for key storage mode */
static pthread_mutex_t gDebugMutex = PTHREAD_MUTEX_INITIALIZER;  /* Mutex for debug output */
static pthread_mutex_t gFileMutex = PTHREAD_MUTEX_INITIALIZER;

/* Bitcoin high-value address search variables */
static HighValuePubKey *gPubKeys = NULL;  /* Array of public keys from CSV */
static Cpa32U gPubKeyCount = 0;           /* Number of loaded public keys */
extern char *gMasterFilePath;  /* Default path */
extern Cpa32U gBatchSize;
extern CpaBoolean gSequentialMode;
extern CpaBoolean gDebugMode;
extern Cpa32U gNumThreads;
extern Cpa64U gMaxKeysToCheck;  /* 0 means unlimited */
extern CpaBoolean gKeyStorageMode;
extern char *gKeyStoragePath;
extern Cpa64U gStartKeyIndex;
extern Cpa64U gNumKeysToGenerate;

/* Maximum number of threads */
#define MAX_THREADS 64

/* Thread data structures */
typedef struct {
    CpaInstanceHandle instanceHandle;
    Cpa32U instanceNum;  /* Add back the instance number for identification */
    Cpa32U startIteration;
    Cpa32U numIterations;
    CpaStatus status;
} thread_data_t;

/* Key storage thread data structure */
typedef struct {
    CpaInstanceHandle instanceHandle;
    Cpa32U instanceNum;  /* Instance number for identification */
    Cpa64U startIndex;
    Cpa64U numKeys;
    const char *storagePath;
    Cpa32U threadId;
    Cpa32U startBatchIndex;
} KeyStorageThreadData;

/* Progress reporting thread data structure */
typedef struct {
    Cpa64U totalKeys;
    const char *storagePath;
} ProgressThreadData;

/* Variables for key distribution statistics */
Cpa32U gTotalNonZeroBytes = 0;
Cpa32U gTotalUniqueValues = 0;
Cpa32U gThreadsReporting = 0;
pthread_mutex_t gStatsMutex = PTHREAD_MUTEX_INITIALIZER;

/* Global variables for state saving/resuming */
static Cpa64U gLastSavedKeyCount = 0;
static time_t gLastStateSaveTime = 0;
static const int STATE_SAVE_INTERVAL = 120; /* Save state every 120 seconds */

/* Function declarations */
static CpaStatus generateRandomBytes(Cpa8U *buffer, Cpa32U length);
static CpaStatus generatePrivateKey(Cpa8U *privateKey, const Cpa8U *startKey, CpaBoolean sequentialMode);
static CpaStatus generatePublicKey(const Cpa8U *privateKey, Cpa8U *publicKeyX, Cpa8U *publicKeyY);
static CpaStatus processBatch(CpaInstanceHandle instanceHandle, Cpa32U threadId, Cpa8U *startKey, Cpa32U batchSize, 
                             CpaBoolean sequentialMode, CpaBoolean debugMode);
static void *processingThread(void *arg);
static void *pollingThread(void *arg);
static void *progressReportThread(void *arg);
static void incrementKey(Cpa8U *key);
static Cpa64U getAvailableDiskSpace(const char *path);
static CpaStatus reduceScalar(CpaFlatBuffer *fb);
static void formatUncompressedPubKey(const Cpa8U *publicKeyX, const Cpa8U *publicKeyY, char *hexPubKey);
static CpaStatus createStorageDirectory(const char *storagePath);
/* Non-static functions declared in header file */
CpaStatus initializeQatEcdsa(Cpa16U *pNumInstances, CpaInstanceHandle **pInstances);
CpaStatus cleanupQatEcdsa(void);
CpaStatus runEcdsaExample(void);
CpaStatus ecdsaSecp256k1Sample(void);
CpaStatus generateKeyPair(CpaInstanceHandle instanceHandle, Cpa8U *privateKey, Cpa8U *publicKey);

/* Forward declarations for static functions */
static int compareHighValuePubKeys(const void *a, const void *b);
static CpaStatus loadHighValuePubKeys(const char *filePath);
static void freeHighValuePubKeys(void);
static HighValuePubKey* binarySearchPubKey(const char *pubkey);
static CpaBoolean checkPublicKeyMatch(const char *pubkey);
static CpaStatus checkKeyAgainstHighValue(const Cpa8U *privateKey, const Cpa8U *publicKeyX, const Cpa8U *publicKeyY);

/* Instance handle */
CpaInstanceHandle cyInstHandle = NULL;

/* secp256k1 curve parameters */
/* Prime modulus p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1 */
Cpa8U prime[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F};

/* Curve coefficient a = 0 */
Cpa8U coeff_a[32] = {0};

/* Curve coefficient b = 7 */
Cpa8U coeff_b[32] = {0x07};

/* Order of secp256k1 curve n */
Cpa8U order[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6,
                          0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
                          0xD0, 0x36, 0x41, 0x41, 0x22, 0x63, 0x55, 0x47};

/* Base point G X coordinate of secp256k1 curve */
Cpa8U Bx[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                       0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                       0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                       0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};

/* Base point G Y coordinate of secp256k1 curve */
Cpa8U By[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                       0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                       0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                       0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};

/*****************************************************************************
 * @description
 *     This function reduces scalar to field order value
 *
 * @param[in]  fb  Pointer to flat buffer with scalar value
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
__attribute__((unused))
CpaStatus reduceScalar(CpaFlatBuffer *fb)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaFlatBuffer L = {0};
    Cpa8U *data = NULL;

    if (gDebugMode)
    {
        printf("reduceScalar: Input buffer length: %u bytes\n", fb->dataLenInBytes);
        printf("reduceScalar: Input value: ");
        for (Cpa32U i = 0; i < fb->dataLenInBytes; i++)
        {
            printf("%02x", fb->pData[i]);
        }
        printf("\n");
    }

    /* Allocate memory for L.pData before calling copyToFlatBuffer */
    status = OS_MALLOC(&L.pData, sizeof(order));
    if (status != CPA_STATUS_SUCCESS)
    {
        if (gDebugMode)
            printf("reduceScalar: Failed to allocate memory for L.pData\n");
        return status;
    }

    /* Prepare L value flat buffer */
    if (CPA_STATUS_SUCCESS == status)
        status = copyToFlatBuffer(&L, order, sizeof(order));

    if (status != CPA_STATUS_SUCCESS && gDebugMode)
    {
        printf("reduceScalar: Failed to copy order to flat buffer\n");
        OS_FREE(L.pData);  /* Free memory if copy fails */
        return status;
    }

    /* Reduce fb % L */
    if (CPA_STATUS_SUCCESS == status)
        status = bigNumMod(fb, fb, &L);

    if (status != CPA_STATUS_SUCCESS && gDebugMode)
    {
        printf("reduceScalar: Failed in bigNumMod operation\n");
        return status;
    }

    if (gDebugMode)
    {
        printf("reduceScalar: After mod operation, length: %u bytes\n", fb->dataLenInBytes);
        printf("reduceScalar: After mod value: ");
        for (Cpa32U i = 0; i < fb->dataLenInBytes; i++)
        {
            printf("%02x", fb->pData[i]);
        }
        printf("\n");
    }

    /* Align output buffer to DATA_LEN for QAT operations */
    if (CPA_STATUS_SUCCESS == status && fb->dataLenInBytes < DATA_LEN)
    {
        status = OS_MALLOC(&data, DATA_LEN);
        if (CPA_STATUS_SUCCESS == status)
        {
            memset(data, 0, DATA_LEN);
            memcpy(data, fb->pData, fb->dataLenInBytes);
            OS_FREE(fb->pData);
            fb->pData = data;
            fb->dataLenInBytes = DATA_LEN;
            
            if (gDebugMode)
            {
                printf("reduceScalar: After alignment, length: %u bytes\n", fb->dataLenInBytes);
                printf("reduceScalar: Final aligned value: ");
                for (Cpa32U i = 0; i < fb->dataLenInBytes; i++)
                {
                    printf("%02x", fb->pData[i]);
                }
                printf("\n");
            }
        }
        else if (gDebugMode)
        {
            printf("reduceScalar: Failed to allocate memory for aligned buffer\n");
        }
    }

    /* Free memory */
    OS_FREE(L.pData);

    return status;
}

/* Helper function to print buffer in hex */
static void printBuffer(const char* label, const Cpa8U *data, Cpa32U len)
{
    Cpa32U i;
    
    printf("%s (len=%u):\n", label, len);
    for (i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
    }
    printf("\n");
}

/* Helper function to convert hex character to integer */
static int hex2int(char ch) {
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    return -1;
}

/* Helper function to convert hex string to binary */
static void hex2bin(const char *hex, Cpa8U *bin, int len) {
    for (int i = 0; i < len; i++) {
        bin[i] = (hex2int(hex[i*2]) << 4) | hex2int(hex[i*2 + 1]);
    }
}

/* External declarations for utility functions */
extern CpaStatus copyToFlatBuffer(CpaFlatBuffer *dest, const Cpa8U *src, Cpa32U len);
extern CpaStatus memcpy_reverse(Cpa8U *dest, const Cpa8U *src, size_t len);
extern CpaStatus generateRandomBytes(Cpa8U *buffer, Cpa32U length);

/* External declarations for point operations */
extern CpaStatus pointMultiplication(const Cpa8U *pPointX,
                                   const Cpa8U *pPointY,
                                   const Cpa8U *scalar,
                                   Cpa8U *pResultX,
                                   Cpa8U *pResultY);

/* Thread function for instance polling */
static void *pollingThread(void *arg)
{
    CpaInstanceHandle instanceHandle = *(CpaInstanceHandle *)arg;
    while (!gStopThreads)
    {
        icp_sal_CyPollInstance(instanceHandle, 0);
        OS_SLEEP(1);  /* Reduce sleep time from 10ms to 1ms */
    }
    return NULL;
}

/* Thread function for parallel processing */
static void *processingThread(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U startKey[DATA_LEN] = {0};
    Cpa32U batchesProcessed = 0;
    Cpa32U remainingIterations = data->numIterations;

    /* Generate a better distributed starting key based on thread ID */
    if (gSequentialMode) {
        /* Use thread ID to create a more distributed starting point */
        Cpa32U threadId = data->instanceNum;
        
        /* Start with a fully random key for maximum entropy */
        if (generateRandomBytes(startKey, DATA_LEN) != CPA_STATUS_SUCCESS) {
            PRINT_ERR("Failed to generate random bytes for key distribution\n");
            /* Continue anyway with zeros */
            memset(startKey, 0, DATA_LEN);
        }
        
        /* Ensure thread-specific patterns in strategic positions */
        /* Use prime multipliers with thread ID for deterministic but well-distributed values */
        startKey[0] = (threadId * 97) % 256;  /* First byte */
        startKey[8] = (threadId * 101) % 256; /* Quarter point */
        startKey[16] = (threadId * 103) % 256; /* Midpoint */
        startKey[24] = (threadId * 107) % 256; /* Three-quarter point */
        
        /* Use thread ID to influence other bytes in a deterministic way */
        startKey[4] = (threadId * 109) % 256;
        startKey[12] = (threadId * 113) % 256;
        startKey[20] = (threadId * 127) % 256;
        startKey[28] = (threadId * 131) % 256;
        
        /* Also incorporate the starting iteration for sequential distribution within thread */
        Cpa64U currentValue = data->startIteration;
        for (int j = DATA_LEN - 1; j >= DATA_LEN - 8; j--) {
            startKey[j] ^= currentValue & 0xFF;  /* XOR to preserve entropy */
            currentValue >>= 8;
        }
        
        /* Print key distribution statistics */
        pthread_mutex_lock(&gDebugMutex);
        
        /* Always print the thread ID and first/last bytes of the key */
        printf("\nThread %u starting key: %02x...%02x (", threadId, startKey[0], startKey[DATA_LEN-1]);
        
        /* Count non-zero bytes to verify distribution */
        int nonZeroBytes = 0;
        for (int i = 0; i < DATA_LEN; i++) {
            if (startKey[i] != 0) nonZeroBytes++;
        }
        
        /* Print distribution statistics */
        printf("%d/%d non-zero bytes, ", nonZeroBytes, DATA_LEN);
        
        /* Calculate entropy estimate (count unique byte values) */
        int uniqueValues[256] = {0};
        int uniqueCount = 0;
        for (int i = 0; i < DATA_LEN; i++) {
            if (uniqueValues[startKey[i]] == 0) {
                uniqueValues[startKey[i]] = 1;
                uniqueCount++;
            }
        }
        printf("%d unique values)", uniqueCount);
        
        /* In debug mode, also print the full key */
        if (gDebugMode) {
            printf("\n  Full key: ");
            for (int i = 0; i < DATA_LEN; i++) {
                printf("%02x", startKey[i]);
                if ((i+1) % 4 == 0) printf(" "); /* Add space every 4 bytes for readability */
            }
        }
        printf("\n");
        pthread_mutex_unlock(&gDebugMutex);
        
        /* Update global key distribution statistics */
        pthread_mutex_lock(&gStatsMutex);
        gTotalNonZeroBytes += nonZeroBytes;
        gTotalUniqueValues += uniqueCount;
        gThreadsReporting++;
        pthread_mutex_unlock(&gStatsMutex);
    } else {
        /* For non-sequential mode, we'll generate random keys anyway, so this doesn't matter */
        Cpa64U currentValue = data->startIteration;
        for (int j = DATA_LEN - 1; j >= 0; j--) {
            startKey[j] = currentValue & 0xFF;
            currentValue >>= 8;
        }
    }

    /* Process in batches */
    while (remainingIterations > 0 && !gStopThreads)
    {
        /* Calculate batch size for this iteration */
        Cpa32U batchSize = (remainingIterations > gBatchSize) ? gBatchSize : remainingIterations;
        
        /* Process this batch */
        status = processBatch(data->instanceHandle, data->instanceNum, startKey, batchSize, gSequentialMode, gDebugMode);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("\nThread %u: Failed to process batch %u\n", data->instanceNum, batchesProcessed);
            break;
        }
        
        /* Update counters */
        remainingIterations -= batchSize;
        batchesProcessed++;
    }

    __sync_fetch_and_add(&gCompletedThreads, 1);
    data->status = status;
    return NULL;
}

/*****************************************************************************
 * @description
 *     This function generates the public key for secp256k1 by performing
 *     scalar multiplication of the base point G with the private key.
 *     The result is encoded in uncompressed SEC format (0x04 || x || y).
 *
 * @param[in]   privateKey  Pointer to buffer with private key (32 bytes)
 * @param[out]  publicKeyX  Pointer to buffer for public key X coordinate (32 bytes)
 * @param[out]  publicKeyY  Pointer to buffer for public key Y coordinate (32 bytes)
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus generatePublicKey(const Cpa8U *privateKey, Cpa8U *publicKeyX, Cpa8U *publicKeyY)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    /* Perform point multiplication with base point G */
    status = pointMultiplication(Bx, By, privateKey, publicKeyX, publicKeyY);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Point multiplication failed\n");
        return status;
    }

    return status;
}

/*****************************************************************************
 * @description
 *     This function demonstrates ECDSA operations on secp256k1 curve by:
 *     1. Generating multiple key pairs with incrementing seeds
 *     2. Comparing each generated public key with a known key
 *
 * @retval CPA_STATUS_SUCCESS       All operations completed successfully.
 * @retval CPA_STATUS_FAIL          One or more operations failed.
 *
 *****************************************************************************/
CpaStatus runEcdsaExample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    const Cpa32U defaultMaxIterations = 3840000000;
    Cpa32U maxIterations = defaultMaxIterations;
    thread_data_t *threadData = NULL;
    struct timespec start, end;
    double cpu_time_used;
    double keys_per_second;
    double years_to_try_all;
    Cpa32U i;
    const int barWidth = 50;
    Cpa32U lastDisplayedCount = 0;

    /* Initialize counters */
    gMatchCount = 0;
    gIterationCount = 0;
    gStopThreads = CPA_FALSE;
    gCompletedThreads = 0;

    /* If max keys is specified, use that instead of default */
    if (gMaxKeysToCheck > 0) {
        if (gMaxKeysToCheck < defaultMaxIterations) {
            maxIterations = (Cpa32U)gMaxKeysToCheck;
        } else {
            maxIterations = defaultMaxIterations;
            printf("Warning: Maximum keys to check exceeds internal limit. Setting to %u\n", maxIterations);
        }
    }

    /* Start timing */
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Allocate thread data */
    status = OS_MALLOC(&threadData, sizeof(thread_data_t) * gNumThreads);
    if (status != CPA_STATUS_SUCCESS)
    {
        PRINT_ERR("Could not allocate memory for thread data\n");
        return CPA_STATUS_FAIL;
    }

    /* Allocate memory for thread handles */
    gThreads = malloc(sizeof(pthread_t) * gNumThreads);
    if (gThreads == NULL)
    {
        PRINT_ERR("Could not allocate memory for thread handles\n");
        OS_FREE(threadData);
        return CPA_STATUS_FAIL;
    }

    /* Allocate memory for polling thread handles */
    gPollingThreads = malloc(sizeof(pthread_t) * gNumThreads);
    if (gPollingThreads == NULL)
    {
        PRINT_ERR("Could not allocate memory for polling thread handles\n");
        OS_FREE(threadData);
        free(gThreads);
        return CPA_STATUS_FAIL;
    }

    /* Initialize progress display */
    printf("\nStarting key search with %u threads...\n", gNumThreads);
    if (gMaxKeysToCheck > 0) {
        printf("Will check up to %llu keys\n", (unsigned long long)gMaxKeysToCheck);
    } else {
        printf("Will run until manually stopped (Ctrl+C) or a match is found\n");
    }
    printf("Progress: [%*s] %3d%%", barWidth, "", 0);
    fflush(stdout);

    /* Create threads with sequential ranges */
    Cpa64U iterationsPerThread = maxIterations / gNumThreads;
    for (i = 0; i < gNumThreads; i++)
    {
        threadData[i].instanceHandle = gInstances[i % gNumInstances];  
        threadData[i].instanceNum = i % gNumInstances;  /* Add instance number for identification */
        threadData[i].startIteration = i * iterationsPerThread;  
        threadData[i].numIterations = iterationsPerThread;

        /* Start polling thread for this instance */
        if (pthread_create(&gPollingThreads[i], NULL, pollingThread, &gInstances[i % gNumInstances]) != 0)
        {
            PRINT_ERR("Failed to create polling thread %u\n", i);
            status = CPA_STATUS_FAIL;
            gStopThreads = CPA_TRUE;
            break;
        }

        /* Start processing thread */
        if (pthread_create(&gThreads[i], NULL, processingThread, &threadData[i]) != 0)
        {
            PRINT_ERR("Failed to create processing thread %u\n", i);
            status = CPA_STATUS_FAIL;
            gStopThreads = CPA_TRUE;
            break;
        }
    }

    /* Monitor progress while threads are running */
    while (__sync_fetch_and_add(&gCompletedThreads, 0) < gNumThreads)
    {
        Cpa32U currentCount = __sync_fetch_and_add(&gIterationCount, 0);
        
        /* Check if we've reached the maximum number of keys */
        if (gMaxKeysToCheck > 0 && currentCount >= gMaxKeysToCheck) {
            printf("\nReached maximum number of keys to check (%llu). Stopping...\n", 
                   (unsigned long long)gMaxKeysToCheck);
            gStopThreads = CPA_TRUE;
        }
        
        if (currentCount > lastDisplayedCount + 1000 || currentCount >= maxIterations)
        {
            /* Calculate progress */
            double progress;
            if (gMaxKeysToCheck > 0) {
                progress = (double)currentCount / gMaxKeysToCheck;
                if (progress > 1.0) progress = 1.0;
            } else {
                /* If no limit is set, just show progress within the current batch */
                progress = (double)currentCount / maxIterations;
            }
            int pos = barWidth * progress;

            /* Print progress bar */
            printf("\rProgress: [");
            for (i = 0; i < barWidth; i++) {
                if (i < pos) printf("=");
                else if (i == pos) printf(">");
                else printf(" ");
            }
            printf("] %3d%% (%u keys)", (int)(progress * 100.0), currentCount);
            fflush(stdout);
            lastDisplayedCount = currentCount;
        }
        usleep(100000);  /* Sleep for 100ms to reduce CPU usage */
    }

    /* Get end time and calculate statistics */
    clock_gettime(CLOCK_MONOTONIC, &end);
    cpu_time_used = ((double)(end.tv_sec - start.tv_sec) +
                    (double)(end.tv_nsec - start.tv_nsec) / 1.0e9);
    keys_per_second = (double)gIterationCount / cpu_time_used;
    
    /* Calculate collision probability based on loaded addresses */
    double addresses_loaded = (double)gPubKeyCount;
    double total_keyspace = pow(2, 256) - 1;
    double collision_probability = addresses_loaded / total_keyspace;
    
    /* Calculate expected keys to check before finding a match (1/probability) */
    double expected_keys_to_check = 1.0 / collision_probability;
    
    /* Calculate time to find a match at current rate */
    double seconds_to_find_match = expected_keys_to_check / keys_per_second;
    double years_to_find_match = seconds_to_find_match / (365 * 24 * 60 * 60);
    
    /* Calculate time to try all keys */
    years_to_try_all = total_keyspace / (keys_per_second * 365 * 24 * 60 * 60);

    /* Print final statistics */
    printf("\n\nFinal Statistics:\n");
    printf("- Total keys checked: %u\n", gIterationCount);
    printf("- Time taken: %.2f seconds\n", cpu_time_used);
    printf("- Average throughput: %.1f keys/sec\n", keys_per_second);
    printf("- Average throughput per instance: %.1f keys/sec\n",
           keys_per_second / gNumInstances);

    /* Print retry statistics only at the end */
    printRetryStats(cpu_time_used);

    printf("\nCollision Probability Analysis:\n");
    printf("- High-value addresses loaded: %.0f\n", addresses_loaded);
    printf("- Collision probability: %.2e (1 in %.2e)\n", collision_probability, 1.0/collision_probability);
    printf("- Expected keys to check before match: %.2e\n", expected_keys_to_check);
    printf("- At current rate (%.2f keys/sec):\n", keys_per_second);
    printf("  * Estimated time to find a match: %.2e years\n", years_to_find_match);
    printf("  * Time to search all keys (2^256): %.2e years\n", years_to_try_all);
    
    if (gMatchCount == 0)
    {
        PRINT_DBG("\nSearch Results:\n");
        PRINT_DBG("- No matching key pairs found after %u iterations\n", gIterationCount);
        PRINT_DBG("- Try running with more iterations or different seed values\n");
    }
    else
    {
        PRINT_DBG("\nSearch Results:\n");
        PRINT_DBG("- Found %u matching key pairs!\n", gMatchCount);
    }

    PRINT_DBG("\n");  /* Add spacing before system summary */
    
    /* Print key distribution statistics */
    pthread_mutex_lock(&gStatsMutex);
    printf("\nKey Distribution Statistics:\n");
    printf("- Total non-zero bytes: %u/%u (%.2f%%)\n", gTotalNonZeroBytes, gThreadsReporting * DATA_LEN, 
           (double)gTotalNonZeroBytes / (gThreadsReporting * DATA_LEN) * 100.0);
    printf("- Total unique values: %u/%u (%.2f%%)\n", gTotalUniqueValues, gThreadsReporting * 256, 
           (double)gTotalUniqueValues / (gThreadsReporting * 256) * 100.0);
    pthread_mutex_unlock(&gStatsMutex);
    
    /* Clean up resources */
    if (threadData) OS_FREE(threadData);
    if (gThreads) free(gThreads);
    if (gPollingThreads) free(gPollingThreads);

    return status;
}

CpaStatus generateKeyPair(CpaInstanceHandle instanceHandle, Cpa8U *privateKey, Cpa8U *publicKey)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U publicKeyX[DATA_LEN] = {0};
    Cpa8U publicKeyY[DATA_LEN] = {0};

    /* Generate random private key */
    status = generateRandomBytes(privateKey, DATA_LEN);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to generate random private key\n");
        return status;
    }

    /* Generate corresponding public key */
    status = generatePublicKey(privateKey, publicKeyX, publicKeyY);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to generate public key\n");
        return status;
    }

    /* Combine X and Y coordinates into uncompressed public key format */
    publicKey[0] = 0x04;  /* Uncompressed point format */
    memcpy(publicKey + 1, publicKeyX, DATA_LEN);
    memcpy(publicKey + 1 + DATA_LEN, publicKeyY, DATA_LEN);

    return status;
}

void comparePublicKeys(const Cpa8U *generatedPublicKey, const Cpa8U *privateKey, const char *knownPublicKey) {
    /* Check input parameters */
    if (!generatedPublicKey || !privateKey || !knownPublicKey) {
        PRINT_ERR("Invalid input parameters to comparePublicKeys\n");
        return;
    }

    /* Check known public key length */
    size_t knownKeyLen = strlen(knownPublicKey);
    if (knownKeyLen != (1 + 2 * DATA_LEN) * 2) {  /* *2 because hex string is twice the length */
        PRINT_ERR("Invalid known public key length: %zu (expected %d)\n", 
                  knownKeyLen, (1 + 2 * DATA_LEN) * 2);
        return;
    }

    /* Print the first few iterations for debugging */
    static int debugCount = 0;
    if (debugCount < 1) {
        printf("\nDebug Info (Iteration %d):\n", debugCount);
        printf("Private Key: ");
        printBuffer("", privateKey, DATA_LEN);
        printf("Generated Public Key (X,Y): ");
        printBuffer("", generatedPublicKey, 2 * DATA_LEN);
        printf("Known Public Key (hex): %s\n", knownPublicKey);
        debugCount++;
    }
    
    /* Convert known public key from hex string to binary, skipping the '04' prefix */
    Cpa8U knownKeyBin[2 * DATA_LEN];
    hex2bin(knownPublicKey + 2, knownKeyBin, 2 * DATA_LEN);  // Skip '04' prefix

    /* Compare only the X,Y coordinates */
    int cmpResult = memcmp(generatedPublicKey, knownKeyBin, 2 * DATA_LEN);

    /* Print first mismatch for debugging */
    static int mismatchPrinted = 0;
    if (!mismatchPrinted) {
        int firstDiff = -1;
        for (int i = 0; i < 2 * DATA_LEN; i++) {
            if (generatedPublicKey[i] != knownKeyBin[i]) {
                firstDiff = i;
                break;
            }
        }
        if (firstDiff >= 0) {
            printf("\nFirst mismatch at coordinate byte %d:\n", firstDiff);
            printf("Generated: %02x\n", generatedPublicKey[firstDiff]);
            printf("Expected:  %02x\n", knownKeyBin[firstDiff]);
            printf("Generated key part: ");
            printBuffer("", generatedPublicKey + (firstDiff/32)*32, 32);
            printf("Expected key part:  ");
            printBuffer("", knownKeyBin + (firstDiff/32)*32, 32);
            mismatchPrinted = 1;
        }
    }

    if (cmpResult == 0) {
        __sync_fetch_and_add(&gMatchCount, 1);  /* Atomically increment match counter */
        printf("\nMATCH FOUND!\n");
        printf("Private Key: ");
        printBuffer("", privateKey, DATA_LEN);
        printf("Matching Public Key (X,Y): ");
        printBuffer("", generatedPublicKey, 2 * DATA_LEN);
    }
}

/*****************************************************************************
 * @description
 *     Comparison function for binary search of high-value public keys.
 *     Compares two HighValuePubKey structures by their public key strings.
 *
 * @param[in]  a  Pointer to first HighValuePubKey
 * @param[in]  b  Pointer to second HighValuePubKey
 *
 * @retval < 0  If a's pubkey is less than b's pubkey
 * @retval 0    If a's pubkey equals b's pubkey
 * @retval > 0  If a's pubkey is greater than b's pubkey
 *
 *****************************************************************************/
static int compareHighValuePubKeys(const void *a, const void *b)
{
    const HighValuePubKey *keyA = (const HighValuePubKey *)a;
    const HighValuePubKey *keyB = (const HighValuePubKey *)b;
    
    /* Compare the uncompressed public key strings */
    return strcmp(keyA->pubkey, keyB->pubkey);
}

/*****************************************************************************
 * @description
 *     Load public keys from CSV file and sort them for binary search
 *
 * @param[in]  filePath  Path to CSV file
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus loadHighValuePubKeys(const char *filePath)
{
    FILE *file;
    char line[MAX_CSV_LINE_LENGTH];
    char *token;
    Cpa32U lineCount = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    
    /* Open the CSV file */
    file = fopen(filePath, "r");
    if (!file)
    {
        PRINT_ERR("Failed to open CSV file: %s\n", filePath);
        return CPA_STATUS_FAIL;
    }
    
    /* Count lines in the file */
    while (fgets(line, sizeof(line), file) != NULL)
    {
        lineCount++;
    }
    
    /* Allocate memory for public keys (subtract 1 for header row) */
    gPubKeyCount = lineCount - 1;
    if (gPubKeyCount > MAX_PUBKEYS)
    {
        PRINT_ERR("Too many public keys in CSV file (%u). Maximum is %u.\n", 
                 gPubKeyCount, MAX_PUBKEYS);
        fclose(file);
        return CPA_STATUS_FAIL;
    }
    
    /* Allocate memory for public keys */
    gPubKeys = (HighValuePubKey *)malloc(gPubKeyCount * sizeof(HighValuePubKey));
    if (!gPubKeys)
    {
        PRINT_ERR("Failed to allocate memory for public keys\n");
        fclose(file);
        return CPA_STATUS_FAIL;
    }
    
    /* Reset file position and skip header row */
    rewind(file);
    if (fgets(line, sizeof(line), file) == NULL)
    {
        PRINT_ERR("Failed to read header row from CSV file\n");
        free(gPubKeys);
        gPubKeys = NULL;
        fclose(file);
        return CPA_STATUS_FAIL;
    }
    
    /* Read and parse each line */
    Cpa32U i = 0;
    while (i < gPubKeyCount && fgets(line, sizeof(line), file) != NULL)
    {
        /* Remove newline character */
        line[strcspn(line, "\n")] = 0;
        
        /* Parse CSV fields (address,last_seen_balance,compressed_pubkey,uncompressed_pubkey) */
        char *saveptr;
        
        /* Get address */
        token = strtok_r(line, ",", &saveptr);
        if (!token)
        {
            PRINT_ERR("Invalid CSV format at line %u\n", i + 2);
            continue;
        }
        gPubKeys[i].address = strdup(token);
        
        /* Get balance (second field) */
        token = strtok_r(NULL, ",", &saveptr);
        if (!token)
        {
            PRINT_ERR("Invalid CSV format at line %u\n", i + 2);
            free(gPubKeys[i].address);
            continue;
        }
        gPubKeys[i].balance = strdup(token);
        
        /* Skip compressed public key (third field) */
        token = strtok_r(NULL, ",", &saveptr);
        if (!token)
        {
            PRINT_ERR("Invalid CSV format at line %u\n", i + 2);
            free(gPubKeys[i].address);
            free(gPubKeys[i].balance);
            continue;
        }
        
        /* Get uncompressed public key (fourth field) */
        token = strtok_r(NULL, ",", &saveptr);
        if (!token)
        {
            PRINT_ERR("Invalid CSV format at line %u\n", i + 2);
            free(gPubKeys[i].address);
            free(gPubKeys[i].balance);
            continue;
        }
        gPubKeys[i].pubkey = strdup(token);
        
        i++;
    }
    
    /* Update actual count of loaded keys */
    gPubKeyCount = i;
    
    /* Close the file */
    fclose(file);    
    /* Sort the public keys for binary search */
    qsort(gPubKeys, gPubKeyCount, sizeof(HighValuePubKey), compareHighValuePubKeys);
    
    PRINT_DBG("Loaded and sorted %u public keys from %s\n", gPubKeyCount, filePath);
    
    return status;
}

/*****************************************************************************
 * @description
 *     Free memory allocated for public keys
 *
 *****************************************************************************/
static void freeHighValuePubKeys(void)
{
    if (gPubKeys)
    {
        for (Cpa32U i = 0; i < gPubKeyCount; i++)
        {
            free(gPubKeys[i].address);
            free(gPubKeys[i].balance);
            free(gPubKeys[i].pubkey);
        }
        free(gPubKeys);
        gPubKeys = NULL;
    }
}

/*****************************************************************************
 * @description
 *     Search for a public key using binary search
 *
 * @param[in]  pubkey  Public key to search for (hex string)
 *
 * @retval  Pointer to found public key, or NULL if not found
 *
 *****************************************************************************/
static HighValuePubKey* binarySearchPubKey(const char *pubkey)
{
    int left = 0;
    int right = gPubKeyCount - 1;
    int iterations = 0;
    char debugInfo[2048] = {0};  /* Larger buffer for debug info */
    
    if (gDebugMode)
    {
        /* In debug mode, store the complete search key */
        snprintf(debugInfo, sizeof(debugInfo), 
                "  Search key: %s\n  Comparisons:\n", 
                pubkey);
    }
    
    while (left <= right)
    {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(pubkey, gPubKeys[mid].pubkey);
        
        if (gDebugMode && iterations < 3)  /* Show first 3 comparisons */
        {
            char temp[2048];
            snprintf(temp, sizeof(temp), 
                    "    [%d] Search: %s\n"
                    "        Target: %s\n"
                    "        Result: cmp=%d\n\n", 
                    iterations+1, pubkey, gPubKeys[mid].pubkey, cmp);
            strncat(debugInfo, temp, sizeof(debugInfo) - strlen(debugInfo) - 1);
            iterations++;
        }
        
        if (cmp == 0)
        {
            if (gDebugMode)
            {
                pthread_mutex_lock(&gDebugMutex);
                printf("\n  Binary search result: MATCH FOUND!\n%s\n", debugInfo);
                pthread_mutex_unlock(&gDebugMutex);
            }
            return &gPubKeys[mid];
        }
        
        if (cmp < 0)
            right = mid - 1;
        else
            left = mid + 1;
    }
    
    if (gDebugMode)
    {
        pthread_mutex_lock(&gDebugMutex);
        printf("\n  Binary search result: NO MATCH\n%s\n", debugInfo);
        pthread_mutex_unlock(&gDebugMutex);
    }
    
    return NULL;
}

/*****************************************************************************
 * @description
 *     Convert binary public key coordinates to uncompressed hex format
 *
 * @param[in]  publicKeyX  X coordinate of public key
 * @param[in]  publicKeyY  Y coordinate of public key
 * @param[out] hexPubKey   Buffer to store hex public key (must be at least 131 bytes)
 *
 *****************************************************************************/
static void formatUncompressedPubKey(const Cpa8U *publicKeyX, const Cpa8U *publicKeyY, char *hexPubKey)
{
    /* Format as "04" + X + Y coordinates in hex */
    strcpy(hexPubKey, "04");
    
    /* Append X coordinate */
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexPubKey + 2 + (i * 2), "%02x", publicKeyX[i]);
    }
    
    /* Append Y coordinate */
    for (int i = 0; i < 32; i++)
    {
        sprintf(hexPubKey + 2 + 64 + (i * 2), "%02x", publicKeyY[i]);
    }
}

/*****************************************************************************
 * @description
 *     Initialize the QAT instance for ECDSA operations.
 *
 * @param[out] pNumInstances  Pointer to store the number of instances
 * @param[out] pInstances     Pointer to store the array of instance handles
 *
 * @retval CPA_STATUS_SUCCESS       Initialization successful.
 * @retval CPA_STATUS_FAIL          Initialization failed.
 *
 *****************************************************************************/
CpaStatus initializeQatEcdsa(Cpa16U *pNumInstances, CpaInstanceHandle **pInstances)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i;

    PRINT_DBG("Starting secp256k1 ECDSA sample code...\n");

    /* Initialize memory driver */
    status = qaeMemInit();
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialize memory driver\n");
        return CPA_STATUS_FAIL;
    }

    /* Initialize QAT user process */
    status = icp_sal_userStart("ECDSA");
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to start user process\n");
        qaeMemDestroy();
        return status;
    }

    /* Get the number of crypto instances */
    status = cpaCyGetNumInstances(pNumInstances);
    if (CPA_STATUS_SUCCESS != status || *pNumInstances == 0)
    {
        PRINT_ERR("No crypto instances found\n");
        icp_sal_userStop();
        qaeMemDestroy();
        return CPA_STATUS_FAIL;
    }

    PRINT_DBG("Number of crypto instances: %u\n", *pNumInstances);

    /* Allocate memory for instances */
    status = OS_MALLOC(pInstances, sizeof(CpaInstanceHandle) * *pNumInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to allocate memory for instances\n");
        icp_sal_userStop();
        qaeMemDestroy();
        return status;
    }

    /* Get handles to all instances */
    status = cpaCyGetInstances(*pNumInstances, *pInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to get instance handles\n");
        OS_FREE(*pInstances);
        icp_sal_userStop();
        qaeMemDestroy();
        return status;
    }

    /* Start each instance */
    for (i = 0; i < *pNumInstances; i++)
    {
        status = cpaCyStartInstance((*pInstances)[i]);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to start instance %u\n", i);
            while (i > 0)
            {
                i--;
                cpaCyStopInstance((*pInstances)[i]);
            }
            OS_FREE(*pInstances);
            icp_sal_userStop();
            qaeMemDestroy();
            return status;
        }

        /* Set the address translation function for the instance */
        status = cpaCySetAddressTranslation((*pInstances)[i], sampleVirtToPhys);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to set address translation for instance %u\n", i);
            while (i >= 0)
            {
                cpaCyStopInstance((*pInstances)[i]);
                i--;
            }
            OS_FREE(*pInstances);
            icp_sal_userStop();
            qaeMemDestroy();
            return status;
        }
    }

    /* Set first instance as the default */
    cyInstHandle = (*pInstances)[0];

    return status;
}

CpaStatus cleanupQatEcdsa(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa32U i;

    /* Signal threads to stop */
    gStopThreads = CPA_TRUE;

    /* Stop all instances */
    if (gInstances)
    {
        for (i = 0; i < gNumInstances; i++)
        {
            CpaStatus localStatus = cpaCyStopInstance(gInstances[i]);
            if (CPA_STATUS_SUCCESS != localStatus)
            {
                PRINT_ERR("Failed to stop instance %u\n", i);
                status = localStatus;
            }
        }
        OS_FREE(gInstances);
        gInstances = NULL;
    }

    return status;
}

CpaStatus ecdsaSecp256k1Sample(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    struct timespec start, end;
    double elapsed_time;

    /* Start timing */
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Initialize QAT */
    status = initializeQatEcdsa(&gNumInstances, &gInstances);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialize QAT\n");
        return status;
    }

    /* Load high-value public keys from CSV file */
    status = loadHighValuePubKeys(gMasterFilePath);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to load high-value public keys\n");
        cleanupQatEcdsa();
        return status;
    }

    /* Run the example */
    status = runEcdsaExample();

    /* Clean up */
    cleanupQatEcdsa();
    freeHighValuePubKeys();

    /* Calculate elapsed time */
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_time = ((double)(end.tv_sec - start.tv_sec) +
                    (double)(end.tv_nsec - start.tv_nsec) / 1.0e9);

    /* Print final summary */
    PRINT_DBG("\n=== Execution Summary ===\n");
    PRINT_DBG("Total execution time: %.2f seconds\n", elapsed_time);
    PRINT_DBG("(includes QAT initialization and cleanup)\n\n");

    if (CPA_STATUS_SUCCESS == status)
    {
        PRINT_DBG("Sample completed successfully.\n");
    }
    else
    {
        PRINT_ERR("Sample failed with status: %d\n", status);
    }

    return status;
}

/*****************************************************************************
 * @description
 *     Generate random bytes using CPU's RDRAND instruction.
 *     Intel QAT 1.7+ no longer includes RNG capability as it's available via
 *     CPU instructions RDRAND and RDSEED.
 *
 * @param[out] buffer  Buffer to store random bytes
 * @param[in]  length  Number of random bytes to generate
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus generateRandomBytes(Cpa8U *buffer, Cpa32U length)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    unsigned long long rand_val;
    Cpa32U i;

    if (!buffer || length == 0)
    {
        PRINT_ERR("Invalid parameters\n");
        return CPA_STATUS_INVALID_PARAM;
    }

    /* Generate random bytes using RDRAND */
    for (i = 0; i < length; i += sizeof(unsigned long long))
    {
        /* Try RDRAND up to 10 times */
        int retries = 10;
        unsigned char success;

        while (retries-- > 0)
        {
            /* Use RDRAND instruction to get random value */
            asm volatile(".byte 0x48, 0x0f, 0xc7, 0xf0" /* RDRAND %rax */
                        : "=a" (rand_val), "=@ccc" (success));
            
            if (success)
                break;
            
            /* Small delay before retry */
            asm volatile("pause");
        }

        if (!success)
        {
            PRINT_ERR("RDRAND instruction failed after multiple attempts\n");
            return CPA_STATUS_FAIL;
        }

        /* Copy random bytes to buffer */
        Cpa32U bytes_to_copy = ((length - i) < sizeof(unsigned long long)) ? 
                              (length - i) : sizeof(unsigned long long);
        memcpy(buffer + i, &rand_val, bytes_to_copy);
    }

    return status;
}

static CpaStatus generatePrivateKey(Cpa8U *privateKey, const Cpa8U *startKey, CpaBoolean sequentialMode)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    
    if (sequentialMode && startKey)
    {
        /* Copy the start key and increment it */
        memcpy(privateKey, startKey, DATA_LEN);              
        incrementKey(privateKey);
        
    }
    else
    {
        /* Generate random private key */
        status = generateRandomBytes(privateKey, DATA_LEN);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to generate random bytes for private key\n");
            return status;
        }
    }
    
    /* Check if the key is zero (invalid) */
    Cpa32U i;
    CpaBoolean isZero = CPA_TRUE;
    for (i = 0; i < DATA_LEN; i++)
    {
        if (privateKey[i] != 0)
        {
            isZero = CPA_FALSE;
            break;
        }
    }
    
    if (isZero)
    {
        /* If key is zero, set it to 1 (simplest valid private key) */
        if (gDebugMode)
            printf("Private key was zero, setting to 1\n");
        memset(privateKey, 0, DATA_LEN);
        privateKey[DATA_LEN - 1] = 1;
    }
    
    /* We'll skip the reduction step for now since it's causing issues */
    /* The probability of a random 256-bit number exceeding the curve order is extremely small */
    
    return status;
}

static char* getDirectoryPath(const char* filePath) {
    char* dirPath = strdup(filePath);
    if (!dirPath) return NULL;
    
    char* lastSlash = strrchr(dirPath, '/');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';  /* Keep the trailing slash */
    } else {
        /* No slash found, use current directory */
        free(dirPath);
        dirPath = strdup("./");
    }
    
    return dirPath;
}

static void saveMatchToFile(const char* address, const char* balance, 
                           const char* publicKey, const Cpa8U* privateKey) {
    FILE* file;
    char* dirPath;
    char* outputPath;
    char privateKeyHex[DATA_LEN * 2 + 1] = {0};
    time_t now;
    struct tm* timeinfo;
    char timestamp[20];
    
    /* Get current timestamp */
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", timeinfo);
    
    /* Convert private key to hex string */
    for (int i = 0; i < DATA_LEN; i++) {
        sprintf(privateKeyHex + (i * 2), "%02x", privateKey[i]);
    }
    
    /* Get directory of master file */
    if (!gMasterFilePath) {
        PRINT_ERR("Master file path not set, using current directory\n");
        dirPath = strdup("./");
    } else {
        dirPath = getDirectoryPath(gMasterFilePath);
    }
    
    if (!dirPath) {
        PRINT_ERR("Failed to allocate memory for directory path\n");
        return;
    }
    
    /* Create output file path */
    size_t pathLen = strlen(dirPath) + 32;  /* Extra space for filename */
    outputPath = (char*)malloc(pathLen);
    if (!outputPath) {
        PRINT_ERR("Failed to allocate memory for output path\n");
        free(dirPath);
        return;
    }
    
    snprintf(outputPath, pathLen, "%smatches_%s.csv", dirPath, timestamp);
    
    /* Lock file access to prevent race conditions */
    pthread_mutex_lock(&gFileMutex);
    
    /* Open file in append mode */
    file = fopen(outputPath, "a");
    if (!file) {
        PRINT_ERR("Failed to open output file: %s\n", outputPath);
        pthread_mutex_unlock(&gFileMutex);
        free(dirPath);
        free(outputPath);
        return;
    }
    
    /* Write header if file is new (empty) */
    fseek(file, 0, SEEK_END);
    if (ftell(file) == 0) {
        fprintf(file, "address,balance,public_key,private_key\n");
    }
    
    /* Write match details */
    fprintf(file, "%s,%s,%s,%s\n", address, balance, publicKey, privateKeyHex);
    
    /* Close file */
    fclose(file);
    pthread_mutex_unlock(&gFileMutex);
    
    printf("Match details saved to: %s\n", outputPath);
    
    /* Clean up */
    free(dirPath);
    free(outputPath);
}

static CpaStatus checkKeyAgainstHighValue(const Cpa8U *privateKey, const Cpa8U *publicKeyX, const Cpa8U *publicKeyY)
{
    char hexPubKey[133]; /* 04 + 64 hex chars for X + 64 hex chars for Y + null terminator */
    HighValuePubKey *match;
    
    /* Format the public key as uncompressed hex string */
    formatUncompressedPubKey(publicKeyX, publicKeyY, hexPubKey);
    
    /* Check if this key matches any high-value address */
    if (checkPublicKeyMatch(hexPubKey))
    {
        /* Found a match! */
        __sync_fetch_and_add(&gMatchCount, 1);
        
        /* Get the matching record for details */
        match = binarySearchPubKey(hexPubKey);
        
        /* Print the match details */
        printf("\n\n🎉 MATCH FOUND! 🎉\n");
        printf("Address: %s\n", match->address);
        printf("Balance: %s BTC\n", match->balance);
        printf("Public Key: %s\n", hexPubKey);
        
        /* Print the private key */
        printf("Private Key: ");
        for (int i = 0; i < DATA_LEN; i++) {
            printf("%02x", privateKey[i]);
        }
        printf("\n\n");
        
        /* Save match details to CSV file */
        saveMatchToFile(match->address, match->balance, hexPubKey, privateKey);
    }
    else if (gDebugMode)
    {
        /* In debug mode, show the binary search result */
        pthread_mutex_lock(&gDebugMutex);
        printf("  Binary search: No match found for public key\n");
        pthread_mutex_unlock(&gDebugMutex);
    }
    
    return CPA_STATUS_SUCCESS;
}

static CpaStatus processBatch(CpaInstanceHandle instanceHandle, Cpa32U threadId, Cpa8U *startKey, Cpa32U batchSize, 
                             CpaBoolean sequentialMode, CpaBoolean debugMode)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa8U privateKey[DATA_LEN];
    Cpa8U publicKeyX[DATA_LEN];
    Cpa8U publicKeyY[DATA_LEN];
    Cpa8U currentKey[DATA_LEN];
    
    /* Initialize the current key */
    if (startKey)
    {
        memcpy(currentKey, startKey, DATA_LEN);
    }
    else
    {
        status = generateRandomBytes(currentKey, DATA_LEN);
    }
    
    /* Process each key in the batch */
    for (Cpa32U i = 0; i < batchSize && !gStopThreads; i++)
    {
        /* Generate private key */
        status = generatePrivateKey(privateKey, currentKey, sequentialMode);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to generate private key\n");
            return status;
        }
        
        /* Save the current key for the next iteration */
        memcpy(currentKey, privateKey, DATA_LEN);
        
        /* Generate public key */
        status = generatePublicKey(privateKey, publicKeyX, publicKeyY);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to generate public key\n");
            return status;
        }
        
        if (debugMode)
        {
            pthread_mutex_lock(&gDebugMutex);
            printf("\n🔍 [Thread %u] Key #%u:\n", threadId, i+1);
            printf("  Private key: ");
            for (int j = 0; j < DATA_LEN; j++)
            {
                printf("%02x", privateKey[j]);
            }
            
            printf("\n  Public key X: ");
            for (int j = 0; j < DATA_LEN; j++)
            {
                printf("%02x", publicKeyX[j]);
            }
            
            printf("\n  Public key Y: ");
            for (int j = 0; j < DATA_LEN; j++)
            {
                printf("%02x", publicKeyY[j]);
            }
            
            printf("\n  Full public key: 04");
            for (int j = 0; j < DATA_LEN; j++)
            {
                printf("%02x", publicKeyX[j]);
            }
            for (int j = 0; j < DATA_LEN; j++)
            {
                printf("%02x", publicKeyY[j]);
            }
            printf("\n");
            pthread_mutex_unlock(&gDebugMutex);
        }
        
        /* Check if this key matches any high-value address */
        status = checkKeyAgainstHighValue(privateKey, publicKeyX, publicKeyY);
        if (CPA_STATUS_SUCCESS != status)
        {
            PRINT_ERR("Failed to check key against high-value addresses\n");
            return status;
        }
        
        /* Increment the global counter */
        __sync_fetch_and_add(&gIterationCount, 1);
    }
    
    return status;
}

/*****************************************************************************
 * @description
 *     Increment a 32-byte private key by 1, handling carry operations
 *
 * @param[in,out] key  32-byte private key to increment
 *
 *****************************************************************************/
 static void incrementKey(Cpa8U *key)
 {
     int i;
     
     /* Start from least significant byte (last byte) */
     for (i = 31; i >= 0; i--)
     {
         /* Increment the current byte */
         key[i]++;
         
         /* If no overflow, we're done */
         if (key[i] != 0)
             break;
         
         /* Otherwise, carry to next byte */
         /* (loop continues to next iteration) */
     }
 }

/*****************************************************************************
 * @description
 *     Check if a public key matches any in the high-value addresses list
 *
 * @param[in]  pubKeyHex  Uncompressed public key in hex format
 *
 * @retval CPA_TRUE   Match found
 * @retval CPA_FALSE  No match found
 *
 *****************************************************************************/
 static CpaBoolean checkPublicKeyMatch(const char *pubKeyHex)
 {
     /* Use binary search to efficiently find a match */
     HighValuePubKey *match = binarySearchPubKey(pubKeyHex);
     
     if (match)
     {
         /* Match found */
         return CPA_TRUE;
     }
     
     /* No match found */
     return CPA_FALSE;
 }

/**
 * @brief Saves the current state to a file for resuming later
 * 
 * @param storagePath Path where key files are stored
 * @param currentKeyCount Current number of keys generated
 * @param lastBatchIndex Last batch index written
 * @return CpaStatus CPA_STATUS_SUCCESS if successful, CPA_STATUS_FAIL otherwise
 */
static CpaStatus saveStateFile(const char *storagePath, Cpa64U currentKeyCount, Cpa32U lastBatchIndex) {
    FILE *stateFile;
    char statePath[1024];
    time_t currentTime;
    
    /* Only save state if enough time has passed since last save */
    time(&currentTime);
    if (currentTime - gLastStateSaveTime < STATE_SAVE_INTERVAL && 
        currentKeyCount - gLastSavedKeyCount < KEY_STORAGE_BATCH_SIZE) {
        return CPA_STATUS_SUCCESS;
    }
    
    snprintf(statePath, sizeof(statePath), "%s/resume_state.json", storagePath);
    
    stateFile = fopen(statePath, "w");
    if (!stateFile) {
        PRINT_ERR("Failed to create state file: %s\n", statePath);
        return CPA_STATUS_FAIL;
    }
    
    fprintf(stateFile, "{\n");
    fprintf(stateFile, "  \"current_key_count\": %llu,\n", (unsigned long long)currentKeyCount);
    fprintf(stateFile, "  \"last_batch_index\": %u,\n", lastBatchIndex);
    fprintf(stateFile, "  \"timestamp\": %ld,\n", (long)currentTime);
    fprintf(stateFile, "  \"version\": \"1.0\"\n");
    fprintf(stateFile, "}\n");
    
    fclose(stateFile);
    
    /* Update globals */
    gLastSavedKeyCount = currentKeyCount;
    gLastStateSaveTime = currentTime;
    
    return CPA_STATUS_SUCCESS;
}

/**
 * @brief Loads the state from a file for resuming
 * 
 * @param storagePath Path where key files are stored
 * @param currentKeyCount Pointer to store the current key count
 * @param lastBatchIndex Pointer to store the last batch index
 * @return CpaStatus CPA_STATUS_SUCCESS if successful, CPA_STATUS_FAIL if file not found or invalid
 */
static CpaStatus loadStateFile(const char *storagePath, Cpa64U *currentKeyCount, Cpa32U *lastBatchIndex) {
    FILE *stateFile;
    char statePath[1024];
    char buffer[1024];
    
    snprintf(statePath, sizeof(statePath), "%s/resume_state.json", storagePath);
    
    stateFile = fopen(statePath, "r");
    if (!stateFile) {
        /* State file doesn't exist, not an error */
        return CPA_STATUS_FAIL;
    }
    
    /* Simple JSON parsing */
    *currentKeyCount = 0;
    *lastBatchIndex = 0;
    
    while (fgets(buffer, sizeof(buffer), stateFile) != NULL) {
        /* Parse current_key_count */
        if (strstr(buffer, "\"current_key_count\"")) {
            sscanf(buffer, "  \"current_key_count\": %llu,", (unsigned long long*)currentKeyCount);
        }
        
        /* Parse last_batch_index */
        if (strstr(buffer, "\"last_batch_index\"")) {
            sscanf(buffer, "  \"last_batch_index\": %u,", lastBatchIndex);
        }
    }
    
    fclose(stateFile);
    
    /* Validate loaded values */
    if (*currentKeyCount == 0) {
        PRINT_ERR("Invalid state file: %s\n", statePath);
        return CPA_STATUS_FAIL;
    }
    
    printf("Resuming from previous state: %llu keys generated, last batch index: %u\n", 
           (unsigned long long)*currentKeyCount, *lastBatchIndex);
    
    return CPA_STATUS_SUCCESS;
}

/**
 * @brief Checks if a batch file exists
 * 
 * @param storagePath Path where key files are stored
 * @param batchIndex Batch index to check
 * @return CpaBoolean CPA_TRUE if file exists, CPA_FALSE otherwise
 */
CpaBoolean batchFileExists(const char *storagePath, Cpa32U batchIndex) {
    char batchPath[1024];
    FILE *batchFile;
    
    snprintf(batchPath, sizeof(batchPath), "%s/batch_%08u.dat", storagePath, batchIndex);
    
    batchFile = fopen(batchPath, "r");
    if (batchFile) {
        fclose(batchFile);
        return CPA_TRUE;
    }
    
    return CPA_FALSE;
}

/**
 * @brief Creates a metadata JSON file for the key storage
 * 
 * @param storagePath Path where key files are stored
 * @param startIndex Starting index for key generation
 * @param endIndex Ending index for key generation
 * @return CpaStatus CPA_STATUS_SUCCESS if successful, CPA_STATUS_FAIL otherwise
 */
static CpaStatus createMetadataFile(const char *storagePath, Cpa64U startIndex, Cpa64U endIndex) {
    FILE *metadataFile;
    char metadataPath[1024];
    
    snprintf(metadataPath, sizeof(metadataPath), "%s/metadata.json", storagePath);
    
    metadataFile = fopen(metadataPath, "w");
    if (!metadataFile) {
        PRINT_ERR("Failed to create metadata file: %s\n", metadataPath);
        return CPA_STATUS_FAIL;
    }
    
    fprintf(metadataFile, "{\n");
    fprintf(metadataFile, "  \"start_index\": %llu,\n", (unsigned long long)startIndex);
    fprintf(metadataFile, "  \"end_index\": %llu,\n", (unsigned long long)endIndex);
    fprintf(metadataFile, "  \"record_format\": {\n");
    fprintf(metadataFile, "    \"priv_key\": { \"size\": %d, \"type\": \"bytes\" },\n", KEY_STORAGE_PRIV_KEY_SIZE);
    fprintf(metadataFile, "    \"pub_key_x\": { \"size\": %d, \"type\": \"bytes\" },\n", KEY_STORAGE_PUBKEY_X_SIZE);
    fprintf(metadataFile, "    \"pub_key_y\": { \"size\": %d, \"type\": \"bytes\" }\n", KEY_STORAGE_PUBKEY_Y_SIZE);
    fprintf(metadataFile, "  },\n");
    fprintf(metadataFile, "  \"record_size\": %d,\n", KEY_STORAGE_RECORD_SIZE);
    fprintf(metadataFile, "  \"block_size\": %d,\n", KEY_STORAGE_BLOCK_SIZE);
    fprintf(metadataFile, "  \"keys_per_block\": %d,\n", KEY_STORAGE_KEYS_PER_BLOCK);
    fprintf(metadataFile, "  \"batch_size\": %d,\n", KEY_STORAGE_BATCH_SIZE);
    fprintf(metadataFile, "  \"endianness\": \"big-endian\",\n");
    fprintf(metadataFile, "  \"created_at\": \"%s\"\n", __DATE__ " " __TIME__);
    fprintf(metadataFile, "}\n");
    
    fclose(metadataFile);
    printf("Created metadata file: %s\n", metadataPath);
    
    return CPA_STATUS_SUCCESS;
}

/**
 * @brief Writes a batch of key records to a file
 * 
 * @param storagePath Path where key files are stored
 * @param batchIndex Batch index (for filename)
 * @param records Array of key records
 * @param numRecords Number of records to write
 * @return CpaStatus
 */
static CpaStatus writeBatchFile(const char *storagePath, Cpa32U batchIndex, 
                               const Cpa8U *records, Cpa32U numRecords) {
    FILE *batchFile;
    char batchPath[1024];
    size_t recordsSize = numRecords * KEY_STORAGE_RECORD_SIZE;
    
    /* Create batch filename */
    snprintf(batchPath, sizeof(batchPath), "%s/keys_batch_%04u.dat", storagePath, batchIndex);
    
    batchFile = fopen(batchPath, "wb");
    if (!batchFile) {
        PRINT_ERR("Failed to create batch file: %s\n", batchPath);
        return CPA_STATUS_FAIL;
    }
    
    /* Write records in one go */
    if (fwrite(records, 1, recordsSize, batchFile) != recordsSize) {
        PRINT_ERR("Failed to write records to batch file: %s\n", batchPath);
        fclose(batchFile);
        return CPA_STATUS_FAIL;
    }
    
    fclose(batchFile);
    printf("Created batch file: %s (%u records, %lu bytes)\n", 
           batchPath, numRecords, (unsigned long)recordsSize);
    
    return CPA_STATUS_SUCCESS;
}

/**
 * @brief Stores a private key and public key data in a record
 * 
 * @param record Buffer to store the record (must be at least KEY_STORAGE_RECORD_SIZE bytes)
 * @param privateKey Full private key (32 bytes)
 * @param publicKeyX X coordinate of public key (32 bytes)
 * @param publicKeyY Y coordinate of public key (32 bytes)
 */
static void createKeyRecord(Cpa8U *record, const Cpa8U *privateKey, const Cpa8U *publicKeyX, const Cpa8U *publicKeyY) {
    /* Store full private key (32 bytes) */
    memcpy(record, privateKey, KEY_STORAGE_PRIV_KEY_SIZE);
    
    /* Store X coordinate (32 bytes) */
    memcpy(record + KEY_STORAGE_PRIV_KEY_SIZE, publicKeyX, KEY_STORAGE_PUBKEY_X_SIZE);
    
    /* Store Y coordinate (32 bytes) */
    memcpy(record + KEY_STORAGE_PRIV_KEY_SIZE + KEY_STORAGE_PUBKEY_X_SIZE, 
           publicKeyY, KEY_STORAGE_PUBKEY_Y_SIZE);
}

/**
 * @brief Thread function for generating and storing keys
 */
static void *keyStorageThread(void *arg) {
    KeyStorageThreadData *threadData = (KeyStorageThreadData *)arg;
    CpaInstanceHandle instanceHandle = threadData->instanceHandle;
    Cpa32U threadId = threadData->threadId;
    Cpa64U startIndex = threadData->startIndex;
    Cpa64U numKeys = threadData->numKeys;
    const char *storagePath = threadData->storagePath;
    Cpa32U batchStartIndex = threadData->startBatchIndex;
    
    Cpa8U privateKey[DATA_LEN];
    Cpa8U publicKeyX[DATA_LEN];
    Cpa8U publicKeyY[DATA_LEN];
    CpaStatus status = CPA_STATUS_SUCCESS;
    Cpa64U i, keysGenerated = 0;
    Cpa32U currentBatchIndex = batchStartIndex;
    Cpa32U keysInCurrentBatch = 0;
    Cpa32U recordsPerBatch = KEY_STORAGE_BATCH_SIZE;
    Cpa8U *batchRecords = NULL;
    
    printf("Thread %u starting key generation from index %llu, generating %llu keys\n",
           threadId, (unsigned long long)startIndex, (unsigned long long)numKeys);
    
    /* Allocate memory for batch records */
    batchRecords = (Cpa8U *)malloc(recordsPerBatch * KEY_STORAGE_RECORD_SIZE);
    if (!batchRecords) {
        PRINT_ERR("Thread %u: Failed to allocate memory for batch records\n", threadId);
        return (void *)CPA_STATUS_FAIL;
    }
    
    /* Generate keys and store them in batches */
    for (i = 0; i < numKeys && !gStopThreads; i++) {
        Cpa64U keyIndex = startIndex + i;
        
        /* Generate random private key */
        status = generateRandomBytes(privateKey, DATA_LEN);
        if (status != CPA_STATUS_SUCCESS) {
            PRINT_ERR("Thread %u: Failed to generate random private key\n", threadId);
            continue;
        }
        
        /* Generate public key */
        Cpa8U fullPublicKey[1 + 2 * DATA_LEN]; /* Format: 0x04 + X + Y coordinates */
        status = generateKeyPair(instanceHandle, privateKey, fullPublicKey);
        if (status != CPA_STATUS_SUCCESS) {
            PRINT_ERR("Thread %u: Failed to generate key pair for index %llu\n", 
                      threadId, (unsigned long long)keyIndex);
            continue;
        }
        
        /* Extract X and Y coordinates from the full public key */
        memcpy(publicKeyX, fullPublicKey + 1, DATA_LEN);
        memcpy(publicKeyY, fullPublicKey + 1 + DATA_LEN, DATA_LEN);
        
        /* Create key record */
        createKeyRecord(batchRecords + (keysInCurrentBatch * KEY_STORAGE_RECORD_SIZE),
                       privateKey, publicKeyX, publicKeyY);
        
        keysInCurrentBatch++;
        keysGenerated++;
        
        /* Increment global counter for progress reporting */
        __sync_fetch_and_add(&gTotalKeysGenerated, 1);
        
        /* Write batch to disk if full */
        if (keysInCurrentBatch >= recordsPerBatch) {
            status = writeBatchFile(storagePath, currentBatchIndex, batchRecords, keysInCurrentBatch);
            if (status != CPA_STATUS_SUCCESS) {
                PRINT_ERR("Thread %u: Failed to write batch file %u\n", threadId, currentBatchIndex);
                break;
            }
            
            currentBatchIndex++;
            keysInCurrentBatch = 0;
            
            /* Print progress - avoid division by zero for fill-disk mode */
            if (numKeys > 0) {
                printf("Thread %u: Generated %llu keys (%.2f%%)\n", 
                       threadId, (unsigned long long)keysGenerated, 
                       (double)keysGenerated * 100.0 / numKeys);
            } else {
                printf("Thread %u: Generated %llu keys\n", 
                       threadId, (unsigned long long)keysGenerated);
            }
            
            /* Flush stdout to ensure progress is visible */
            fflush(stdout);
            
            /* Save state periodically */
            saveStateFile(storagePath, gTotalKeysGenerated, currentBatchIndex);
        }
    }
    
    /* Write any remaining keys */
    if (keysInCurrentBatch > 0) {
        status = writeBatchFile(storagePath, currentBatchIndex, batchRecords, keysInCurrentBatch);
        if (status != CPA_STATUS_SUCCESS) {
            PRINT_ERR("Thread %u: Failed to write final batch file %u\n", threadId, currentBatchIndex);
        }
        
        /* Save final state */
        saveStateFile(storagePath, gTotalKeysGenerated, currentBatchIndex + 1);
    }
    
    /* Clean up */
    free(batchRecords);
    
    printf("Thread %u: Completed key generation, generated %llu keys\n", 
           threadId, (unsigned long long)keysGenerated);
    
    return (void *)((intptr_t)((status == CPA_STATUS_SUCCESS) ? 0 : 1));
}

/**
 * @brief Calculate the maximum number of keys that can be stored on the disk
 * 
 * @param storagePath Path to the storage location
 * @return Cpa64U Maximum number of keys that can be stored
 */
static Cpa64U calculateMaxKeys(const char *storagePath) {
    // Get available disk space
    Cpa64U availableBytes = getAvailableDiskSpace(storagePath);
    if (availableBytes == 0) {
        return 0;
    }
    
    // Reserve 10MB for metadata and other files
    const Cpa64U reservedBytes = 10 * 1024 * 1024;
    if (availableBytes <= reservedBytes) {
        PRINT_ERR("Not enough disk space available\n");
        return 0;
    }
    
    availableBytes -= reservedBytes;
    
    // Calculate how many keys we can store
    // Each key record is KEY_STORAGE_RECORD_SIZE bytes (38 bytes)
    Cpa64U maxKeys = availableBytes / KEY_STORAGE_RECORD_SIZE;
    
    // Round down to a multiple of KEY_STORAGE_BATCH_SIZE for efficient batch processing
    maxKeys = (maxKeys / KEY_STORAGE_BATCH_SIZE) * KEY_STORAGE_BATCH_SIZE;
    
    printf("Can store approximately %llu keys on the disk\n", 
           (unsigned long long)maxKeys);
           
    return maxKeys;
}

/**
 * @brief Generate and store Bitcoin keys to disk
 * 
 * @param startIndex Starting index for key generation
 * @param numKeys Number of keys to generate (0 to fill disk)
 * @param storagePath Path to store the keys
 * @param forceRestart If true, ignore any existing state and start fresh
 * @return CpaStatus
 */
CpaStatus generateAndStoreKeys(Cpa64U startIndex, Cpa64U numKeys, const char *storagePath, CpaBoolean forceRestart) {
    CpaStatus status = CPA_STATUS_SUCCESS;
    KeyStorageThreadData *threadData = NULL;
    pthread_t *threads = NULL;
    Cpa64U keysPerThread;
    Cpa32U numThreads;
    Cpa32U i;
    Cpa16U numInstances = 0;
    CpaInstanceHandle *instances = NULL;
    pthread_t progressThread;
    ProgressThreadData progressData;
    Cpa64U resumeKeyCount = 0;
    Cpa32U resumeBatchIndex = 0;
    CpaBoolean resuming = CPA_FALSE;
    
    /* Initialize QAT */
    status = initializeQatEcdsa(&numInstances, &instances);
    if (status != CPA_STATUS_SUCCESS) {
        return status;
    }
    
    /* Create storage directory if it doesn't exist */
    status = createStorageDirectory(storagePath);
    if (status != CPA_STATUS_SUCCESS) {
        cleanupQatEcdsa();
        return status;
    }
    
    /* Check if we should resume from previous state */
    if (!forceRestart) {
        status = loadStateFile(storagePath, &resumeKeyCount, &resumeBatchIndex);
        if (status == CPA_STATUS_SUCCESS) {
            resuming = CPA_TRUE;
            /* Adjust startIndex based on resumed key count */
            startIndex += resumeKeyCount;
            
            /* If we're in fill disk mode, we need to recalculate numKeys */
            if (numKeys == 0) {
                numKeys = calculateMaxKeys(storagePath);
                if (numKeys == 0) {
                    cleanupQatEcdsa();
                    return CPA_STATUS_FAIL;
                }
                
                /* Adjust for already generated keys */
                if (numKeys <= resumeKeyCount) {
                    printf("Disk is already full. Nothing to do.\n");
                    cleanupQatEcdsa();
                    return CPA_STATUS_SUCCESS;
                }
                
                numKeys -= resumeKeyCount;
                printf("Resuming fill disk mode: %llu more keys to generate\n", 
                       (unsigned long long)numKeys);
            } else {
                /* Adjust for already generated keys */
                if (numKeys <= resumeKeyCount) {
                    printf("All requested keys have already been generated. Nothing to do.\n");
                    cleanupQatEcdsa();
                    return CPA_STATUS_SUCCESS;
                }
                
                numKeys -= resumeKeyCount;
                printf("Resuming: %llu more keys to generate\n", (unsigned long long)numKeys);
            }
            
            /* Initialize global key count with resumed value */
            gTotalKeysGenerated = resumeKeyCount;
        }
    }
    
    /* If we're in fill disk mode (numKeys == 0), calculate how many keys we can store */
    if (numKeys == 0) {
        numKeys = calculateMaxKeys(storagePath);
        if (numKeys == 0) {
            cleanupQatEcdsa();
            return CPA_STATUS_FAIL;
        }
        
        printf("Filling disk with %llu keys\n", (unsigned long long)numKeys);
    }
    
    /* Create metadata file */
    status = createMetadataFile(storagePath, startIndex, startIndex + numKeys - 1);
    if (status != CPA_STATUS_SUCCESS) {
        cleanupQatEcdsa();
        return status;
    }
    
    /* Determine number of threads to use */
    numThreads = numInstances;
    if (numThreads > MAX_THREADS) {
        numThreads = MAX_THREADS;
    }
    
    /* Allocate thread data and thread handles */
    threadData = (KeyStorageThreadData *)malloc(numThreads * sizeof(KeyStorageThreadData));
    threads = (pthread_t *)malloc(numThreads * sizeof(pthread_t));
    if (!threadData || !threads) {
        PRINT_ERR("Failed to allocate memory for thread data\n");
        free(threadData);
        free(threads);
        cleanupQatEcdsa();
        return CPA_STATUS_FAIL;
    }
    
    /* Calculate keys per thread */
    keysPerThread = (numKeys + numThreads - 1) / numThreads;
    
    /* Adjust for batch size */
    if (keysPerThread % KEY_STORAGE_BATCH_SIZE != 0) {
        keysPerThread = ((keysPerThread / KEY_STORAGE_BATCH_SIZE) + 1) * KEY_STORAGE_BATCH_SIZE;
    }
    
    /* Ensure we don't exceed the total keys */
    if (keysPerThread * numThreads > numKeys) {
        keysPerThread = numKeys / numThreads;
        if (numKeys % numThreads != 0) {
            keysPerThread++;
        }
    }
    
    /* Initialize global key count if not resuming */
    if (!resuming) {
        gTotalKeysGenerated = 0;
    }
    
    /* Reset stop flag */
    gStopThreads = 0;
    
    /* Start progress reporting thread */
    progressData.totalKeys = numKeys + resumeKeyCount; /* Total including already generated keys */
    progressData.storagePath = storagePath;
    if (pthread_create(&progressThread, NULL, progressReportThread, &progressData)) {
        PRINT_ERR("Failed to create progress thread\n");
        free(threadData);
        free(threads);
        cleanupQatEcdsa();
        return CPA_STATUS_FAIL;
    }
    
    /* Create and start worker threads */
    for (i = 0; i < numThreads; i++) {
        threadData[i].instanceHandle = instances[i % numInstances];
        threadData[i].threadId = i;
        threadData[i].instanceNum = i % numInstances;
        threadData[i].storagePath = storagePath;
        
        /* Calculate start index and number of keys for this thread */
        threadData[i].startIndex = startIndex + (i * keysPerThread);
        threadData[i].numKeys = keysPerThread;
        
        /* Calculate batch start index for this thread */
        if (resuming && i == 0) {
            /* First thread starts from the resumed batch index */
            threadData[i].startBatchIndex = resumeBatchIndex;
        } else {
            /* Other threads get their batch indices based on thread order */
            threadData[i].startBatchIndex = (i == 0) ? 0 : 
                threadData[i-1].startBatchIndex + 
                ((threadData[i-1].numKeys + KEY_STORAGE_BATCH_SIZE - 1) / KEY_STORAGE_BATCH_SIZE);
        }
        
        if (pthread_create(&threads[i], NULL, keyStorageThread, &threadData[i])) {
            PRINT_ERR("Failed to create thread %u\n", i);
            gStopThreads = 1;
            status = CPA_STATUS_FAIL;
            break;
        }
    }
    
    /* Wait for threads to complete */
    for (i = 0; i < numThreads; i++) {
        void *threadStatus;
        if (pthread_join(threads[i], &threadStatus) != 0) {
            PRINT_ERR("Failed to join thread %u\n", i);
            status = CPA_STATUS_FAIL;
        } else if ((intptr_t)threadStatus != 0) {
            PRINT_ERR("Thread %u failed with status %p\n", i, threadStatus);
            status = CPA_STATUS_FAIL;
        }
    }
    
    /* Signal progress thread to stop */
    gStopThreads = 1;
    
    /* Wait for progress thread to complete */
    void *progressStatus;
    pthread_join(progressThread, &progressStatus);
    
    /* Clean up */
    free(threadData);
    free(threads);
    
    /* Clean up QAT */
    cleanupQatEcdsa();
    
    if (status == CPA_STATUS_SUCCESS) {
        printf("Successfully generated and stored %llu keys\n", (unsigned long long)numKeys);
    } else {
        PRINT_ERR("Failed to generate and store keys\n");
    }
    
    return status;
}

/**
 * @brief Thread function to periodically report progress of key generation
 */
static void *progressReportThread(void *arg) {
    ProgressThreadData *threadData = (ProgressThreadData *)arg;
    Cpa64U totalKeys = threadData->totalKeys;
    const char *storagePath = threadData->storagePath;
    struct timespec startTime, currentTime;
    double elapsedSeconds;
    
    clock_gettime(CLOCK_MONOTONIC, &startTime);
    
    while (!gStopThreads) {
        sleep(5); // Report every 5 seconds
        
        Cpa64U current = gTotalKeysGenerated;
        clock_gettime(CLOCK_MONOTONIC, &currentTime);
        
        elapsedSeconds = (currentTime.tv_sec - startTime.tv_sec) + 
                        (currentTime.tv_nsec - startTime.tv_nsec) / 1000000000.0;
        
        if (elapsedSeconds > 0) {
            double keysPerSecond = current / elapsedSeconds;
            double percentComplete = (totalKeys > 0) ? ((double)current / totalKeys * 100.0) : 0;
            
            // Calculate time remaining
            char timeRemaining[100] = "";
            if (keysPerSecond > 0 && totalKeys > current) {
                Cpa64U keysRemaining = totalKeys - current;
                double secondsRemaining = keysRemaining / keysPerSecond;
                
                // Convert to days, hours, minutes
                int days = (int)(secondsRemaining / 86400);
                secondsRemaining -= days * 86400;
                
                int hours = (int)(secondsRemaining / 3600);
                secondsRemaining -= hours * 3600;
                
                int minutes = (int)(secondsRemaining / 60);
                
                // Format the time remaining string
                if (days > 0) {
                    sprintf(timeRemaining, " - Time remaining: %d days %d hours %d minutes", 
                            days, hours, minutes);
                } else if (hours > 0) {
                    sprintf(timeRemaining, " - Time remaining: %d hours %d minutes", 
                            hours, minutes);
                } else {
                    sprintf(timeRemaining, " - Time remaining: %d minutes", minutes);
                }
            }
            
            printf("\rProgress: %llu/%llu keys (%.2f%%) - %.2f keys/sec%s", 
                  (unsigned long long)current, 
                  (unsigned long long)totalKeys,
                  percentComplete,
                  keysPerSecond,
                  timeRemaining);
            fflush(stdout);
            
            /* Save state periodically */
            saveStateFile(storagePath, current, 0); /* 0 for batch index as we don't know it here */
        }
        
        if (current >= totalKeys) {
            break;
        }
    }
    
    printf("\nKey generation completed!\n");
    return NULL;
}

/**
 * @brief Get available disk space in bytes
 * 
 * @param path Path to the disk location
 * @return Cpa64U Available space in bytes, 0 on error
 */
static Cpa64U getAvailableDiskSpace(const char *path) {
    struct statvfs stat;
    
    if (statvfs(path, &stat) != 0) {
        PRINT_ERR("Failed to get disk space information for %s\n", path);
        return 0;
    }
    
    // Available blocks * block size
    Cpa64U availableBytes = (Cpa64U)stat.f_bavail * stat.f_frsize;
    
    printf("Disk space available at %s: %.2f GB\n", 
           path, (double)availableBytes / (1024 * 1024 * 1024));
           
    return availableBytes;
}

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */

/**
 * @brief Create a directory for storing key files
 * 
 * @param storagePath Path to the storage location
 * @return CpaStatus CPA_STATUS_SUCCESS if successful, CPA_STATUS_FAIL otherwise
 */
static CpaStatus createStorageDirectory(const char *storagePath) {
    // Check if directory already exists
    struct stat sb;
    if (stat(storagePath, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        return CPA_STATUS_SUCCESS;
    }
    
    // Create directory
    if (mkdir(storagePath, 0777) != 0) {
        PRINT_ERR("Failed to create directory: %s\n", storagePath);
        return CPA_STATUS_FAIL;
    }
    
    return CPA_STATUS_SUCCESS;
}
