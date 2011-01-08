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
} /* end crypto_genkey */

crypto_key_return_t crypto_loadkey( const char *filename, metakey_t mk,
                                    size_t keysize) {
    crypto_key_return_t result = KEY_FAILURE;
    FILE *kf = NULL;
    size_t fresult;

    /* ensure library has been initialised */
    if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] library not initialised!\n");
        #endif

        result = LIB_NOT_INIT;
        return result;
    }

    kf = fopen(filename, "r");
    if (0 != ferror(kf)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error opening file %s...\n", filename);
        perror("fopen");
        #endif

        /* if generate_keys is set, we should attempt to generate a new key */
        if (0 != generate_keys) {
            #ifdef DEBUG
            printf("[+] attempting to generate a new key...\n");
            #endif

            /* don't check if the library is initialised, we already checked
             * that...  */
            result = crypto_genkey( mk, keysize );
            if (KEY_SUCCESS == result) {
                return KEYGEN;
            }

            else if (KEY_FAILURE == result) {
                return KEYGEN_ERR;
            }
            
            else {
                return result;
            }
        }

        return KEY_FAILURE;
    }

    /* the keyfile is now open without error */
    mk->keysize = keysize;

    /* calloc memory for the key */
    mk->key = (unsigned char *) CRYPTO_MALLOC( mk->keysize, 
                                               sizeof(unsigned char));
    if (NULL == mk->key) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error allocating memory for key!\n");
        #endif DEBUG

        return result;
    }
    /* key has now been allocated memory */

    /* read keysize + 1 bytes from the file: if we actually read keysize + 1
     * bytes, it means there is a key mismatch. */
    fresult = fread(mk->key, keysize + 1, sizeof(unsigned char), kf);

    if (keysize != fresult) {
        #ifdef DBEUG
        fprintf(stderr, "[!] key size mismatch in file %s: ", filename);
        fprintf(stderr, "expected %u bytes, actually read %u bytes!\n",
                (unsigned int) keysize, (unsigned int) fresult);
        #endif

        /* check to make sure the keyfile closes successfully,
         * if it doesn't close return with an inconsistent state error */
        if (0 != fclose(kf)) {
            #ifdef DEBUG
            fprintf(stderr, "[!] error closing %s!\n", filename);
            #endif

            return INCONSISTENT_STATE;
        } /* end fclose error check */

        if (0 != generate_keys) {
            result = crypto_genkey( mk, keysize );

            if (KEY_SUCCESS == result) {
                return SIZE_MISMATCH;
            }

            else if (KEY_FAILURE == result) {
                return KEYGEN_ERR;
            }

            else {
                return result;
            }
        } /* end automatic key generation */
    } /* end read size check */
    
    /* at this point, the key was loaded without error */
    #ifdef DEBUG
    printf("[+] key successfully loaded!\n");
    #endif

    mk->initialised = 1;

    /* time to close and check for errors */
    if (0 != fclose(kf)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error closing keyfile %s!\n", filename);
        fprintf(stderr, "[!] keyfile may be in an inconsistent state!\n");
        perror("fclose");
        #endif 
        
        result = INCONSISTENT_STATE;
    }

    else {
        result = KEY_SUCCESS;
    }

    return result;
} /* end crypto_loadkey */

crypto_key_return_t crypto_dumpkey( const char *filename, metakey_t mk ) {
    crypto_key_return_t result = KEY_FAILURE;
    FILE *kf = NULL;
    size_t fresult = 0;
    
    if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] library not initialised!\n");
        #endif

        return LIB_NOT_INIT;
    }

    if (1 != mk->initialised) {
        #ifdef DEBUG
        fprintf(stderr, "[!] dumpkey(): attmepted to dump an uninitialised ");
        fprintf(stderr, "key!\n");
        #endif

        return KEY_NOT_INIT;
    }
    
    /* open keyfile and check for errors */
    kf = fopen(filename, "w");
    if (0 != ferror(kf)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error opening %s for write!\n", filename);
        perror("fopen");
        #endif

        return result;
    } /* end fopen error checking */

    /* write key to file and check the appropriate number of bytes were 
     * written into the file */
    fresult = fwrite(mk->key, mk->keysize, sizeof(unsigned char), kf);
    if (mk->keysize != fresult) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error dumping key to %s: ", filename);
        fprintf(stderr, "expected %u bytes, wrote %u bytes!\n",
                (unsigned int) mk->keysize, (unsigned int) fresult);
        #endif

        result = SIZE_MISMATCH;

        /* close keyfile and check for errors */
        if (0 != fclose(kf)) {
            #ifdef DEBUG
            fprintf(stderr, "[!] error closing keyfile. keyfile may be in an ");
            fprintf(stderr, "inconsistent state!\n");
            perror("fclose");
            #endif

            result = INCONSISTENT_STATE;
        }

        return result;
    } /* end size mismatch error handling */


    /* key successfully loaded */
    mk->initialised = 1;

    /* close and check for errors */
    if (0 != fclose(kf)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error closing keyfile %s - keyfile may be in an ",
                filename);
        fprintf(stderr, "inconsistent state!\n");
        perror("fclose");
        #endif

        result = INCONSISTENT_STATE;
    } /* end file close error handling */

    else {
        result = KEY_SUCCESS;
    }

    return result;
} /* end crypto_dumpkey */

