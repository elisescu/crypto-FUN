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

struct crypto_t {
    size_t keysize;
    char *key;
    gcry_cipher_spec_t algo;
    unsigned short int securemem;
};

typedef struct crypto_t ** keyring_t;

enum crypto_op {
    ENCRYPT,
    DECRYPT
};

#endif
