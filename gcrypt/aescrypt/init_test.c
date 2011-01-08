/************************************************************************
 * init_test.c                                                          *
 * 4096R/B7B720D6 "Kyle Isom <coder@kyleisom.net>                       *
 *                                                                      *
 * test initialisation / shutdown code                                  *
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"
#include "cryptoinit.h"

extern keystore_t keystore;

int main( ) {
    keystore = crypto_init( );
    crypto_return_t result = CRYPTO_FAILURE;

    result = crypto_shutdown( );

    return result;
}

