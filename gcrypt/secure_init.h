/*
 * secure_init.h
 * Kyle Isom <coder@kyleisom.net>
 *
 * function definitions and defines for secure_init 
 */


#ifndef __SECURE_INIT_H
#define __SECURE_INIT_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gcrypt.h>

/*
 * defines
 */
#define     GCRYPT_NO_MPI_MACROS        1
#define     GCRYPT_NO_DEPRECATED        1

#define     SECMEM_SZ                   65536
#define     KEYSIZE                     32
#define     ALGO                        GCRY_CIPHER_AES256

#define     KEYFILE                     "aes.key"


/*
 * function declarations
 */

int crypto_init( void );                            /* initialise crypto */
int cryto_shutdown( char *key );                    /* zeroise secure memory 
                                                       and clean up */
int crypto_genkey( char *key );                     /* generate a key */
int crypto_loadkey( char *key );                    /* load key from file */
int crypto_encrypt_file( FILE *inf, FILE *outf, char *key );   
                                                    /* encrypt inf and output
                                                     * as outf. */
#endif
