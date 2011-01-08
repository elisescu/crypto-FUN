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


/*******************************/
/* initialisation and shutdown */
/*******************************/
keystore_t crypto_init( void );
int crypto_shutdown( void );

#endif
