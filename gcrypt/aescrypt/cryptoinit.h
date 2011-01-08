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

/* global keystore */
static keystore_t keystore = NULL;
static int generate_keys = 0;

/*******************************/
/* initialisation and shutdown */
/*******************************/
keystore_t crypto_init( void );
int crypto_shutdown( void );

/*******************************/
/* metakey functions           */
/*******************************/
int crypto_genkey( metakey_t * );
int crypto_loadkey( const char *, metakey_t * );
int crypto_dumpkey( const char *, metakey_t * );
int crypto_zerokey( metakey_t * );

/********************************/
/* keyring functions            */
/********************************/
int crypto_zerokeyring( void );

/********************************/
/* miscellaneous functions      */
/********************************/
int set_autogen( void );
int unset_autogen( void );
int crypto_wipe_keyfile( const char *, int );


#endif
