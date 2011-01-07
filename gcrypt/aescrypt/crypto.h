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
struct metakey_t {
    size_t keysize;
    char *key;
    int algo;
    unsigned short int securemem;
};

/********************************************************************
 * keystore_t:                                                      *
 *      global keystore                                             *
 *                                                                  *
 * store: array of metakey_t's                                      *
 * size: number of keys in the array                                *
 ********************************************************************/
extern struct keystore_t {
    metakey_t **store;
    size_t size;
} key_store;


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

#endif
