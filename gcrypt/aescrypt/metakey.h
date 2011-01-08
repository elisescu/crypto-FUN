/**************************************************************************
 * metakey.h                                                              *
 * 4096R/B7B720D6 "Kyle Isom <coder@kyleisom.net>"                        *
 * 2011-01-08                                                             *
 *                                                                        *
 * defines functions on metakeys - symmetric keys with attached           *
 *  information about the algorithm and keysize.                          *
 **************************************************************************/

#ifndef __METAKEY_H
#define __METAKEY_H

#include "config.h"

#include <gcrypt.h>
#include "crypto.h"

/*******************************/
/* metakey functions           */
/*******************************/
crypto_key_return_t crypto_genkey( metakey_t, size_t );
crypto_key_return_t crypto_loadkey( const char *, metakey_t );
crypto_key_return_t crypto_dumpkey( const char *, metakey_t );
crypto_key_return_t crypto_zerokey( metakey_t );

/********************************/
/* keyring functions            */
/********************************/
crypto_key_return_t crypto_zerokeyring( void );

/********************************/
/* miscellaneous functions      */
/********************************/
crypto_key_return_t set_autogen( void );
crypto_key_return_t unset_autogen( void );
crypto_key_return_t crypto_wipe_keyfile( const char *, int );



#endif
