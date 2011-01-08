/**************************************************************************
 * metakey.c                                                              *
 * 4096/B7B720D6 "Kyle Isom <coder@kylesiom.net>"                         *
 * 2011-01-08                                                             *
 *                                                                        *
 * metakey implementation, see metakey.h for documentation                *
 **************************************************************************/

#include <stdio.h>
#include "metakey.h"


/* key autogeneration flag */
static int generate_keys = 0;

crypto_key_return_t crypto_genkey( metakey_t mk, size_t keysize ) {
    crypto_key_return_t result = KEY_FAILURE;
    mk->keysize = keysize;

    if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        result = KEY_NOT_INIT;

        #ifdef DEBUG
        fprintf(stderr, "[!] crypto library not initialised!\n");
        #endif

        return result;
    }

    /* in the initialisation, we allocated memory for each key already */
    gcry_free(mk->key);     /* need to free it to avoid mem leak */
    mk->key = (unsigned char *) RNG_METHOD( mk->keysize, 
                                            CRYPTO_RANDOM_STRENGTH );

    if (NULL == mk->key) {
        #ifdef DEBUG
        fprintf(stderr, "[!] key generation failed!\n");
        #endif

        return result;
    }

    mk->initialised = 1;

    result = KEY_SUCCESS;
    return result;
}


