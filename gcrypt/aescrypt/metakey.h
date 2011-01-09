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

#include <stdlib.h>

#include "crypto.h"

extern keystore_t keystore;

/**************************************************************************/
/*                  note on automatic key generation                      */
/**************************************************************************/
/* 
 * automatic key generation is determined by the state of the static int
 * generate_keys, and can be interacted with via the set_autogen, 
 * unset_autogen, and autogen_status functions. 
 *
 * automatic key generation takes place under the following conditions:
 *  a key should have been read from keyfile, but either:
 *      1. the file could not be opened
 *      2. the file could be opened but the key read was the wrong size
 *
 * the following crypto_key_return values cover the status of automatic
 * key generation; see crypto.h for their meanings.
 *      KEYGEN, SIZE_MISMATCH, KEYGEN_ERR
 */


/**************************************************************************/
/*                         metakey functions                              */
/**************************************************************************/

/* crypto_genkey: generate a new symmetric key; keys are non-null-terminated
 *                buffers containing unsigned chars.
 *      arguments: the metakey_t containing the key to be generated and
 *                a size_t specifying the key size to generate.
 *      returns: a crypto_key_return_t with the standard error codes 
 *                defined in crypto.h.
 */
extern crypto_key_return_t crypto_genkey( metakey_t, size_t );

/* crypto_loadkey: load a symmetric key from a file. if automatic key
 *                 generation is enabled and there is an error reading the
 *                 key from the file, a key will be generated.
 *      arguments: const char * containing the filename, a metakey_t 
 *                 containing the key to loaded, and a size_t specifying
 *                 the size of the key to be read (and possibly generated).
 *      returns: a crypto_key_return_t with the standard error codes defined
 *                 in crypto.h. of particular note is that if the
 *                function returns with INCONSISTENT_STATE, no key was 
 *                generated or loaded, and the metakey_t is not initialised
 */
extern crypto_key_return_t crypto_loadkey( const char *, metakey_t, size_t );

/* crypto_dumpkey: write a symmetric key to a file. automatic key generation
 *                 is not used in the event of error, as it is assumed the
 *                 key specified is already valid. if the filename already 
 *                 exists, it will be overwritten.
 *      arguments: const char * containaing the file to be written (which
 *                 will be overwritten if it already exists), and a 
 *                 metakey_t containing the key to be written. the keysize
 *                 in the metakey_t will be used to define the size of the
 *                 key to be written.
 *      returns: a crypto_key_return_t with the standard error codes 
 *                 defined in crypto.h. note that a SIZE_MISMATCH return
 *                 does not indicate the key was generated; 
 */
extern crypto_key_return_t crypto_dumpkey( const char *, metakey_t );

/* crypto_zerokey: zeroise a key. the key is randomised with a nonce of
 *                 the same size as the key, then every byte is set to 0.
 *      arguments: a metakey_t to be blanked
 *      returns: a crypto_key_return_t returning one of the following codes:
 *                 KEY_FAILURE, KEY_SUCCESS, KEY_NOT_INIT, LIB_NOT_INIT
 */
extern crypto_key_return_t crypto_zerokey( metakey_t );

/********************************/
/* keyring functions            */
/********************************/
extern crypto_key_return_t crypto_zerokeystore( keystore_t keystore );

/********************************/
/* miscellaneous functions      */
/********************************/

/* this collection of functions activate, deactivate, and return the status
 * respectively of the automatic key generation behaviour. see the header
 * crypto.h for more information on this feature.
 */
extern void crypto_set_autogen( void );
extern void crypto_unset_autogen( void );
extern int crypto_autogen_status( void );



#endif
