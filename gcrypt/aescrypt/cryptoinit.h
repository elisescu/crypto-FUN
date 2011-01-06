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

#include <stdlib.h>
#include <gcrypt.h>

/* defines */

/************************/
/* function definitions */
/************************/

/*
 * crypto_init: initialise gcrypt library *
 *      arguments: none
 *      returns: zero on success, non-zero on error
 */
int crypto_init( void );

/*
 * crypto_shutdown: zeroise any secure memory and close out session
 *      arguments: an array of crypto_t structs
 *      returns: zero on success, non-zero on error
 */
int crypto_shutdown( struct crypto_t **keyring);

/*
 * cryrpto_genkey: generate a key
 *      arguments: a crypto_t struct with information about the key
 *      returns: zero on success, non-zero on failure
 */
int crypto_genkey( struct crypto_t *keydata );

/*
 * crypto_loadkeyfile: load a key from a file
 *      arguments: a crypto_t struct with information about the key
 *      returns: zero on success, non-zero on failure
 */
int crypto_loadkeyfile( struct crypto_t *keydata );

/*
 * crypto_dumpkey: dump key to file
 *      arguments: a const char* storing the file's name, a crypto_t struct
 *                 with info about the key
 *      returns: zero on success, non-zero on failure
 */
int crypto_dumpkey( const char *keyfile, struct crypto_t *keydata );

/*
 * crypto_destroykeyfile: overwrite the keyfile a given number of times
 *                 with cryptographically random data
 *      arguments: const char * storing the keyfile's name, a size_t with
 *                 the number of passes to overwrite the file with
 *      returns: zero on success, non-zero on failure
 */
int crypto_destroykeyfile( const char *keyfile, size_t passes = 1 );

