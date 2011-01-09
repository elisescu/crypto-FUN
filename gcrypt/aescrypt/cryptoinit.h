/*
 * cryptoinit.h
 * Kyle Isom <coder@kyleisom.net>
 * 2011-01-06
 *
 * function declarations and defines for cryptographic initialisation
 */

#ifndef __CRYPTOINIT_H
#define __CRYPTOINIT_H

#include "config.h"
#include "crypto.h"

#include <stdlib.h>
#include <gcrypt.h>


/* global variables */
extern keystore_t keystore;

/**************************************************************************/
/*                    initialisation and shutdown                         */
/**************************************************************************/

/* crypto_init: initialise the crypto libraries and keystore
 *      arguments: none
 *      returns: the address of the allocated keystore on success, NULL if
 *               the keystore could not be initialised.
 */
keystore_t crypto_init( void );

/* crypto_shutdown: shutdown the crypto librarys, destroy secure memory,
 *                  and free the keystore memory
 *      arguments: none
 *      returns: 
 *          CRYPTO_SUCCESS on success
 *          CRYPTO_FAILURE if there was an error shutting down
 *          CRYPTO_NOT_INIT if the crypto libraries have not been 
 *              initialised yet.
 */
crypto_return_t crypto_shutdown( void );

#endif
