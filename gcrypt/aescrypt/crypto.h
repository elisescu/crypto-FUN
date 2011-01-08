/*
 * crypto.h
 * Kyle Isom <coder@kyleisom.net>
 * 2011-01-05
 * 
 * general purpose declarations for the aescrypt program.
 */


#ifndef __CRYPT_H
#define __CRYPT_H

#include <gcrypt.h>
#include <stdlib.h>

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
    char *key;
    int algo;
    unsigned short int securemem;
};

typedef struct metakey * metakey_t;

/********************************************************************
 * keystore_t:                                                      *
 *      global keystore                                             *
 *                                                                  *
 * store: array of metakey_t's                                      *
 * size: number of keys in the array                                *
 ********************************************************************/
extern struct keystore_s {
    metakey_t *store;
    size_t size;
} keystore;

typedef struct keystore keystore_t;

/**************************************************************************
 *                                enums                                   *
 **************************************************************************/

/********************************************************************
 * crypto_op:                                                       *
 *      enumeration for various crypto operations                   *
 *                                                                  *
 * null: operator not initialised                                   *
 ********************************************************************/
enum crypto_op {
    null    = 0,
    encrypt,
    decrypt
};

/********************************************************************
 * crypto_key_return_t:                                             *
 *      return type enumeration for the key generation functions    *
 *                                                                  *
 * failed:  operation failed                                        *
 * success: operation succeeded as intended                         *
 * keygen:  the key should have been loaded the key file was empty  *
 *          and the key was generated. after verifying the file     *
 *          keyfile name, the key should be written using dumpkey   *
 *          this behaviour is only triggered when the global        *
 *          variable generate_keys is set to 1.                     *
 * size_mismatch: the key loaded from the file didn't match the     *
 *          expected key size. if the global generate_keys is set   *
 *          to 1, a new key was generated.                          *
 * keygen_err: according to generate_keys, a key should have been   *
 *          generated but the generation failed.                    *
 ********************************************************************/
 enum crypto_key_return_t {
    failed          = -1,
    success,
    keygen,
    size_mismatch,
    keygen_err
};


#endif
