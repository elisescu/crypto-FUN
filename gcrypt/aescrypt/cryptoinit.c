/*
 * cryptoinit.c
 * Kyle Isom <coder@kyleisom.net>
 * 2011-01-06
 *
 * cryptographic initialisation functions, including key generation 
 */

//#include "crypto.h"
#include "cryptoinit.h"

/* crypto initialisation */
keystore_t crypto_init( ) {
    return key_store;
}

