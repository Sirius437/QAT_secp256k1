/**
 *****************************************************************************
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

/**
 *****************************************************************************
 * @file cpa_eddsa_sample.h
 *
 * @description
 *     This file contains declarations of functions used in ECDSA operations
 *     on the secp256k1 curve.
 *
 *****************************************************************************/

#ifndef CPA_EDDSA_SAMPLE_H
#define CPA_EDDSA_SAMPLE_H

#include "cpa.h"
#include "cpa_cy_ec.h"

#if CY_API_VERSION_AT_LEAST(2, 3)

/*****************************************************************************
 * @description
 *     Signs a message hash using ECDSA with secp256k1. The signature is
 *     computed as (r,s) where:
 *     k = random nonce
 *     R = k*G = (x1,y1)
 *     r = x1 mod n
 *     s = k^(-1)(z + r*d) mod n
 *     where z is the message hash and d is the private key.
 *
 * @param[in]   privateKey   Private key (32 bytes)
 * @param[in]   messageHash  Message hash to sign (32 bytes)
 * @param[out]  signature    Buffer for signature (64 bytes: r || s)
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus signMessage(const Cpa8U *privateKey, const Cpa8U *messageHash, Cpa8U *signature);

/*****************************************************************************
 * @description
 *     Verifies an ECDSA signature on secp256k1. Verifies that:
 *     u1 = z*s^(-1) mod n
 *     u2 = r*s^(-1) mod n
 *     (x1,y1) = u1*G + u2*Q
 *     r = x1 mod n
 *     where z is the message hash and Q is the public key.
 *
 * @param[in]  publicKey    Public key in uncompressed SEC format (65 bytes)
 * @param[in]  messageHash  Message hash that was signed (32 bytes)
 * @param[in]  signature    Signature to verify (64 bytes: r || s)
 *
 * @retval CPA_STATUS_SUCCESS       Signature verification passed
 * @retval CPA_STATUS_FAIL          Signature verification failed
 *
 *****************************************************************************/
CpaStatus verifySignature(const Cpa8U *publicKey, const Cpa8U *messageHash, const Cpa8U *signature);

/*****************************************************************************
 * @description
 *     Runs a complete example of ECDSA operations on secp256k1 curve:
 *     1. Generates a key pair
 *     2. Signs a test message
 *     3. Verifies the signature
 *
 * @retval CPA_STATUS_SUCCESS       All operations completed successfully.
 * @retval CPA_STATUS_FAIL          One or more operations failed.
 *
 *****************************************************************************/
CpaStatus runEcdsaExample(void);

/* Constants for secp256k1 operations */
#define DATA_LEN (32)                          /* Length of curve parameters/coordinates */
#define UNCOMPRESSED_POINT_LEN (65)            /* Length of uncompressed SEC point (0x04 || x || y) */
#define HASH_LEN (32)                          /* Length of SHA-256 hash */
#define SIGNATURE_LEN (64)                     /* Length of ECDSA signature (r,s) */

/* Bitcoin key generation constants */
#define MAX_CSV_LINE_LENGTH 1024
#define MAX_PUBKEYS 1000000  /* Maximum number of public keys to load */

/* Key storage constants */
#define KEY_STORAGE_PRIV_KEY_SIZE 32   /* 32 bytes for full private key */
#define KEY_STORAGE_PUBKEY_X_SIZE 32   /* 32 bytes for full X coordinate */
#define KEY_STORAGE_PUBKEY_Y_SIZE 32   /* 32 bytes for full Y coordinate */
#define KEY_STORAGE_RECORD_SIZE (KEY_STORAGE_PRIV_KEY_SIZE + KEY_STORAGE_PUBKEY_X_SIZE + KEY_STORAGE_PUBKEY_Y_SIZE)
#define KEY_STORAGE_BLOCK_SIZE 4096     /* 4KB blocks for disk performance */
#define KEY_STORAGE_KEYS_PER_BLOCK (KEY_STORAGE_BLOCK_SIZE / KEY_STORAGE_RECORD_SIZE)
#define KEY_STORAGE_BATCH_SIZE 100000  /* Number of keys per batch file */
#define KEY_STORAGE_DEFAULT_PATH "/media/damien/DATA_DISK_1/bitcoin_keys"  /* Default storage path */

/* Bitcoin high-value address structure */
typedef struct {
    char *pubkey;            /* Uncompressed public key (hex string) */
    char *address;           /* Bitcoin address */
    char *balance;           /* Balance in BTC */
} HighValuePubKey;

/* Constants */
#define PRIVATE_KEY_LEN (32)                   /* Length of private key in bytes */
#define PUBLIC_KEY_LEN (64)                    /* Length of public key (x,y) in bytes */
#define HASH_LEN (32)                          /* Length of SHA-256 hash */
#define SIGNATURE_LEN (64)                     /* Length of ECDSA signature (r,s) */

/* Known public key in uncompressed format (04 || x || y) */
extern const char *knownUncompressedPublicKey;

/* ECDSA operations */
CpaStatus generateKeyPair(CpaInstanceHandle instanceHandle, Cpa8U *privateKey, Cpa8U *publicKey);

/* QAT initialization */
CpaStatus initializeQatEcdsa(Cpa16U *pNumInstances, CpaInstanceHandle **pInstances);

/*****************************************************************************
 * @description
 *     Clean up the QAT instance and free resources.
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          One or more cleanup operations failed.
 *
 *****************************************************************************/
CpaStatus cleanupQatEcdsa(void);

/* Example function */
CpaStatus runEcdsaExample(void);

/*****************************************************************************
 * @description
 *     This function demonstrates ECDSA operations on secp256k1 curve by
 *     generating Bitcoin private keys and checking them against high-value addresses.
 *
 * @retval CPA_STATUS_SUCCESS       All operations completed successfully.
 * @retval CPA_STATUS_FAIL          One or more operations failed.
 *
 *****************************************************************************/
CpaStatus ecdsaSecp256k1Sample(void);

/* Utility functions */
CpaStatus copyToFlatBuffer(CpaFlatBuffer *dest, const Cpa8U *src, Cpa32U len);
CpaStatus bigNumMod(CpaFlatBuffer *r, CpaFlatBuffer *a, CpaFlatBuffer *m);

/*****************************************************************************
 * @description
 *     Compares a generated public key with a known public key.
 *     The generated public key is expected to be in binary format with X and Y coordinates,
 *     while the known public key is expected to be in hex string format starting with '04'
 *     (uncompressed SEC format).
 *
 * @param[in]  generatedPublicKey  Generated public key in binary format (64 bytes: x || y)
 * @param[in]  privateKey         Associated private key (32 bytes)
 * @param[in]  knownPublicKey     Known public key in hex string format (130 chars)
 *                                starting with '04' for uncompressed format
 *
 *****************************************************************************/
void comparePublicKeys(const Cpa8U *generatedPublicKey, const Cpa8U *privateKey, const char *knownPublicKey);

/* Global variables */
extern Cpa32U gBatchSize;
extern CpaBoolean gSequentialMode;
extern CpaBoolean gDebugMode;
extern Cpa32U gNumThreads;
extern char *gMasterFilePath;
extern Cpa64U gMaxKeysToCheck;  /* Maximum number of keys to check before stopping */
extern CpaBoolean gKeyStorageMode; /* Flag to enable key storage mode */
extern char *gKeyStoragePath;    /* Path to store key files */
extern Cpa64U gStartKeyIndex;    /* Starting index for key generation */
extern Cpa64U gNumKeysToGenerate; /* Number of keys to generate in storage mode */

/*****************************************************************************
 * @description
 *     Generate and store Bitcoin keys to disk
 * 
 * @param[in]  startIndex     Starting index for key generation
 * @param[in]  numKeys        Number of keys to generate (0 to fill disk)
 * @param[in]  storagePath    Path to store the keys
 * @param[in]  forceRestart   If true, ignore any existing state and start fresh
 *
 * @retval CPA_STATUS_SUCCESS       Function executed successfully.
 * @retval CPA_STATUS_FAIL          Function failed.
 *
 *****************************************************************************/
CpaStatus generateAndStoreKeys(Cpa64U startIndex, Cpa64U numKeys, const char *storagePath, CpaBoolean forceRestart);

/* External variables */
extern CpaInstanceHandle cyInstHandle;
extern int gDebugParam;

#endif /* CY_API_VERSION_AT_LEAST(2, 3) */
#endif /* CPA_EDDSA_SAMPLE_H */
