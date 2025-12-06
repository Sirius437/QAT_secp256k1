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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>  /* For atoi */
#include <getopt.h>  /* For getopt_long */
#include "cpa_sample_utils.h"
#include "icp_sal_user.h"
#include "cpa_cy_ec.h"
#include "cpa_eddsa_sample.h"

/* External declarations for variables defined in cpa_eddsa_sample.c */
extern char *gMasterFilePath;
extern Cpa32U gBatchSize;
extern CpaBoolean gSequentialMode;
extern CpaBoolean gDebugMode;
extern Cpa32U gNumThreads;
extern Cpa64U gMaxKeysToCheck;
extern CpaBoolean gKeyStorageMode;
extern char *gKeyStoragePath;
extern Cpa64U gStartKeyIndex;
extern Cpa64U gNumKeysToGenerate;
extern CpaBoolean gForceRestart;

/* Function declarations */
static CpaStatus parseCommandLine(int argc, char *argv[]);
static void printUsage(const char *programName);

/****************************************************************************
 * @file  cpa_ecdsa_sample_user.c
 *
 * @description
 *     This file contains the main function for the secp256k1 ECDSA sample.
 *     It demonstrates how to use the Intel QuickAssist Technology API for 
 *     performing ECDSA operations on the secp256k1 curve, which is commonly
 *     used in blockchain and cryptocurrency applications.
 *
 ****************************************************************************/

#if CY_API_VERSION_AT_LEAST(2, 3)

extern CpaStatus ecdsaSecp256k1Sample(void);

/* Global debug level - can be set via command line */
int gDebugParam = 1;

/* Forward declarations for functions defined in cpa_eddsa_sample.c */
extern CpaStatus generateAndStoreKeys(Cpa64U startIndex, Cpa64U numKeys, const char *storagePath, CpaBoolean forceRestart);
extern CpaStatus initializeQatEcdsa(Cpa16U *pNumInstances, CpaInstanceHandle **pInstances);
extern CpaStatus cleanupQatEcdsa(void);

/**
 *****************************************************************************
 * @description
 *     Main entry point for the secp256k1 ECDSA sample code. This sample
 *     demonstrates the usage of Intel QuickAssist Technology for performing
 *     ECDSA operations (key generation, signing, and verification) using the
 *     secp256k1 elliptic curve.
 *
 * @param[in]  argc  Number of command line arguments
 * @param[in]  argv  Array of command line arguments
 *                   argv[1] - Optional debug level (0-2, default: 1)
 *                            0: No debug output
 *                            1: Basic debug info
 *                            2: Verbose debug info
 *
 * @retval  0        Sample completed successfully
 * @retval  non-zero Error occurred during sample execution
 *
 *****************************************************************************/
int main(int argc, char *argv[])
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    struct timespec start, end;
    double total_time;

    PRINT_DBG("main(): Starting secp256k1 ECDSA sample code...\n");
    
    /* Parse command line arguments */
    status = parseCommandLine(argc, argv);
    if (status != CPA_STATUS_SUCCESS)
    {
        printUsage(argv[0]);
        return 1;
    }

    /* Start timing */
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Initialize QAT */
    if (gForceRestart) {
        status = qaeMemInit();
    } else {
        /* No resume function exists, just use normal init */
        status = qaeMemInit();
    }
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to initialize memory driver\n");
        return (int)status;
    }

    status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
    if (CPA_STATUS_SUCCESS != status)
    {
        PRINT_ERR("Failed to start user process SSL\n");
        qaeMemDestroy();
        return (int)status;
    }
    
    /* Run the appropriate mode */
    if (gKeyStorageMode)
    {
        /* Key storage mode */
        printf("Running in key storage mode\n");
        printf("Storage path: %s\n", gKeyStoragePath);
        printf("Start index: %llu\n", (unsigned long long)gStartKeyIndex);
        
        if (gNumKeysToGenerate == 0) {
            printf("Number of keys: FILL DISK (will calculate based on available space)\n");
        } else {
            printf("Number of keys: %llu\n", (unsigned long long)gNumKeysToGenerate);
        }
        
        if (gForceRestart) {
            printf("Force restart enabled: Ignoring any previous state\n");
        } else {
            printf("Resume enabled: Will continue from previous state if available\n");
        }
        
        status = generateAndStoreKeys(gStartKeyIndex, gNumKeysToGenerate, gKeyStoragePath, gForceRestart);
    }
    else
    {
        /* Normal mode - search for high-value addresses */
        status = ecdsaSecp256k1Sample();
    }
    
    /* Clean up */
    icp_sal_userStop();
    qaeMemDestroy();

    /* Calculate and report total time */
    clock_gettime(CLOCK_MONOTONIC, &end);
    total_time = ((double)(end.tv_sec - start.tv_sec) +
                 (double)(end.tv_nsec - start.tv_nsec) / 1.0e9);

    printf("=== System Summary ===\n");
    printf("Total execution time: %.2f seconds\n", total_time);
    printf("(includes QAT initialization, cleanup, and system overhead)\n");
    
    if (status == CPA_STATUS_SUCCESS)
    {
        printf("\nSample completed successfully.\n");
        return 0;
    }
    else
    {
        printf("\nSample failed with status %d.\n", status);
        return 1;
    }
}

/*****************************************************************************
 * @description
 *     Parse command line arguments
 *
 * @param[in]  argc  Argument count
 * @param[in]  argv  Argument vector
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
static CpaStatus parseCommandLine(int argc, char *argv[])
{
    int c;
    int option_index = 0;
    CpaStatus status = CPA_STATUS_SUCCESS;
    
    static struct option long_options[] = {
        {"file",       required_argument, 0, 'f'},
        {"batch",      required_argument, 0, 'b'},
        {"sequential", no_argument,       0, 's'},
        {"debug",      no_argument,       0, 'd'},
        {"threads",    required_argument, 0, 't'},
        {"max-keys",   required_argument, 0, 'm'},
        {"help",       no_argument,       0, 'h'},
        {"key-storage", no_argument,      0, 'k'},
        {"storage-path", required_argument, 0, 'p'},
        {"start-index", required_argument, 0, 'i'},
        {"num-keys",   required_argument, 0, 'n'},
        {"force-restart", no_argument,    0, 'r'},
        {0, 0, 0, 0}
    };
    
    while ((c = getopt_long(argc, argv, "f:b:sdt:m:hkp:i:n:r", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 'f':
                gMasterFilePath = optarg;
                break;
                
            case 'b':
                gBatchSize = atoi(optarg);
                if (gBatchSize <= 0)
                {
                    printf("Error: Batch size must be positive\n");
                    return CPA_STATUS_FAIL;
                }
                break;
                
            case 's':
                gSequentialMode = CPA_TRUE;
                break;
                
            case 'd':
                gDebugMode = CPA_TRUE;
                break;
                
            case 't':
                gNumThreads = atoi(optarg);
                if (gNumThreads < 0)
                {
                    printf("Error: Number of threads must be non-negative\n");
                    return CPA_STATUS_FAIL;
                }
                break;
                
            case 'm':
                gMaxKeysToCheck = strtoull(optarg, NULL, 10);
                if (gMaxKeysToCheck <= 0)
                {
                    printf("Error: Maximum keys must be positive (or 0 for unlimited)\n");
                    return CPA_STATUS_FAIL;
                }
                break;
                
            case 'h':
                printUsage(argv[0]);
                exit(0);
                break;
                
            case 'k':
                gKeyStorageMode = CPA_TRUE;
                break;
                
            case 'p':
                gKeyStoragePath = optarg;
                break;
                
            case 'i':
                gStartKeyIndex = strtoull(optarg, NULL, 10);
                break;
                
            case 'n':
                gNumKeysToGenerate = strtoull(optarg, NULL, 10);
                /* Allow 0 to indicate "fill disk" mode */
                if (gNumKeysToGenerate < 0) {
                    printf("Error: Number of keys to generate must be non-negative\n");
                    printf("       (Use 0 to fill the disk completely)\n");
                    return CPA_STATUS_FAIL;
                }
                break;
                
            case 'r':
                gForceRestart = CPA_TRUE;
                break;
                
            case '?':
                /* getopt_long already printed an error message */
                return CPA_STATUS_FAIL;
                
            default:
                printf("Error: Unknown option\n");
                return CPA_STATUS_FAIL;
        }
    }
    
    return status;
}

/*****************************************************************************
 * @description
 *     Print usage information for the program
 *
 * @param[in]  programName  Name of the program
 *
 *****************************************************************************/
static void printUsage(const char *programName)
{
    printf("\nUsage: %s [options]\n\n", programName);
    printf("Bitcoin High-Value Address Search using Intel QAT\n\n");
    printf("Options:\n");
    printf("  -f, --file=FILE       Path to CSV file with high-value addresses\n");
    printf("                        Default: %s\n", gMasterFilePath);
    printf("  -b, --batch=SIZE      Number of keys to check in each batch\n");
    printf("                        Default: %u\n", gBatchSize);
    printf("  -s, --sequential      Use sequential key generation (vs random)\n");
    printf("  -d, --debug           Enable debug mode (print full key pairs)\n");
    printf("  -t, --threads=NUM     Number of threads to use (0 = auto)\n");
    printf("                        Default: %u\n", gNumThreads);
    printf("  -m, --max-keys=NUM    Maximum number of keys to check (0 = unlimited)\n");
    printf("                        Default: 0\n");
    printf("  -h, --help            Display this help and exit\n");
    printf("  -k, --key-storage     Enable key storage mode\n");
    printf("  -p, --storage-path=PATH  Path to store keys\n");
    printf("                        Default: /media/damien/DATA_DISK_1/bitcoin_keys\n");
    printf("  -i, --start-index=INDEX  Start index for key storage\n");
    printf("                        Default: 0\n");
    printf("  -n, --num-keys=NUM      Number of keys to store\n");
    printf("                        Default: 1000000\n");
    printf("                        Use 0 to fill the disk completely\n");
    printf("  -r, --force-restart    Force restart of QAT\n");
}

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */

/* Global variables */
Cpa32U gBatchSize = 1000;
CpaBoolean gSequentialMode = CPA_FALSE;
CpaBoolean gDebugMode = CPA_FALSE;
Cpa32U gNumThreads = 4;
char *gMasterFilePath = "master_high_value_addresses.csv"; //insert your file details 
Cpa64U gMaxKeysToCheck = 0;  /* 0 means unlimited */
CpaBoolean gKeyStorageMode = CPA_FALSE;
char *gKeyStoragePath = KEY_STORAGE_DEFAULT_PATH;
Cpa64U gStartKeyIndex = 0;
Cpa64U gNumKeysToGenerate = 1000000;
CpaBoolean gForceRestart = CPA_FALSE;  /* Default: try to resume if possible */
