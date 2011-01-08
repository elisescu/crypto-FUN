/**************************************************************************
 * crypto.h                                                               *
 * 4096R/B7B720D6 "Kyle Isom <coder@kyleisom.net>"                        *
 * 2011-01-05                                                             *
 *                                                                        *
 * general purpose declarations for the aescrypt program.                 *
 **************************************************************************/


#ifndef __CRYPT_H
#define __CRYPT_H

#include <gcrypt.h>
#include <stdlib.h>

/**************************************************************************
 *                           defines / macros                             *
 **************************************************************************/

/********************************************************************
 * CRYPTO_MALLOC:                                                   *
 *      cryptographic memory allocation                             *
 *                                                                  *
 * allocate a segment of memory, zeroing it first. bases method     *
 * selection on the use of secure memory.                           *
 ********************************************************************/
#ifdef SECURE_MEM
#define     CRYPTO_MALLOC               gcry_calloc_secure

#else
#define     CRYPTO_MALLOC               gcry_calloc

#endif

/********************************************************************
 * CRYPTO_RANDOM_STRENGTH:                                          *
 *      strength of random numbers                                  *
 *                                                                  *
 * if secure memory is used, random numbers will be very strong     *
 * otherwise, strong random numbers with be used                    *
 ********************************************************************/
#ifdef SECURE_MEM
#define     CRYPTO_RANDOM_STRENGTH      GCRY_VERY_STRONG_RANDOM

#else
#define     CRYPTO_RANDOM_STRENGTH      GCRY_STRONG_RANDOM

#endif

/********************************************************************
 * RNG_METHOD:                                                      *
 *      define the RNG function                                     *
 *                                                                  *
 * if secure memory is used, the RNG should allocate from secure    *
 *  memory                                                          *
 * otherwise, pull random numbers from PRNG                         *
 ********************************************************************/
#ifdef SECURE_MEM
#define     RNG_METHOD                  gcryt_random_bytes_secure

#else
#define     RNG_METHOD                  gcrypt_random_bytes

#endif

/**************************************************************************
 *                                structs                                 *
 **************************************************************************/

/********************************************************************
 * metakey_t:                                                       *
 *      symmetric key with additional information attached          *
 *                                                                  *
 * keysize: number of bytes in the key (i.e. 256-bit key has a key- *
 *          size of 32)                                             *
 * key: the raw key bytes                                           *
 * algo: an int specifying one of the gcrypt ciphers                *
 * securemem: this key uses secure memory                           *
 ********************************************************************/
struct metakey {
    size_t keysize;
    unsigned char *key;
    int algo;
    unsigned short sm;
    unsigned short initialised;
};

typedef struct metakey * metakey_t;

/********************************************************************
 * keystore_t:                                                      *
 *      global keystore                                             *
 *                                                                  *
 * store: array of metakey_t's                                      *
 * size: number of keys in the array                                *
 ********************************************************************/
static struct keystore_s {
    metakey_t *store;
    size_t size;
} *keystore;

typedef struct keystore_s * keystore_t; 

/**************************************************************************
 *                                enums                                   *
 **************************************************************************/

/********************************************************************
 * crypto_op_t:                                                     *
 *      enumeration for various crypto operations                   *
 *                                                                  *
 * null: operator not initialised                                   *
 ********************************************************************/
enum crypto_op {
    null    = 0,
    encrypt,
    decrypt
};

typedef enum crypto_op crypto_op_t;

/********************************************************************
 * crypto_key_return_t:                                             *
 *      return type enumeration for the key generation functions    *
 *                                                                  *
 * KEY_FAILED:  key operation failed                                *
 * KEY_SUCCESS: key operation succeeded as intended                 *
 * KEYGEN:  the key should have been loaded the key file was empty  *
 *          and the key was generated. after verifying the file     *
 *          keyfile name, the key should be written using dumpkey   *
 *          this behaviour is only triggered when the global        *
 *          variable generate_keys is set to 1.                     *
 * SIZE_MISMATCH: the key loaded from the file didn't match the     *
 *          expected key size. if the global generate_keys is set   *
 *          to 1, a new key was generated.                          *
 * KEYGEN_ERR: according to generate_keys, a key should have been   *
 *          generated but the generation failed.                    *
 ********************************************************************/
enum crypto_key_return {
    KEY_FAILED          = -1,
    KEY_SUCCESS,
    KEYGEN,
    SIZE_MISMATCH,
    KEYGEN_ERR
};

typedef enum crypto_key_return crypto_key_return_t;

/********************************************************************
 * crypto_return:                                                   *
 *      return codes for cryptographic operations                   *
 *                                                                  *
 * CRYPTO_FAILURE: cryptographic operation failed                   *
 * CRYPTO_SUCCESS: operation succeeded                              *
 * CRYPTO_NOT_INIT: crypto library has not been initialized         *
 ********************************************************************/

enum crypto_return {
    CRYPTO_SUCCESS,
    CRYPTO_FAILURE,
    CRYPTO_NOT_INIT
};

typedef enum crypto_return crypto_return_t;


#endif
