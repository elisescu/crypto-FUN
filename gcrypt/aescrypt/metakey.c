/**************************************************************************
 * metakey.c                                                              *
 * 4096/B7B720D6 "Kyle Isom <coder@kylesiom.net>"                         *
 * 2011-01-08                                                             *
 *                                                                        *
 * metakey implementation, see metakey.h for documentation                *
 **************************************************************************/

#include <stdio.h>
#include <string.h>
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

    /* tmp_key has size keysize + 2 for two reasons:
     *  1. one extra char to detect key size mismatches
     *  2. provide a null terminator to strlen
     */
    unsigned char *tmp_key = (unsigned char *) CRYPTO_MALLOC( keysize + 2,
                                                sizeof(unsigned char));

    /* ensure library has been initialised */
    if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] library not initialised!\n");
        #endif

        result = LIB_NOT_INIT;
        return result;
    }

    #ifdef DEBUG
    printf("[+] attempting to open keyfile %s...\n", filename);
    #endif 

    kf = fopen(filename, "r");
    if ((NULL == kf) || (0 != ferror(kf))) {
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
    gcry_free(mk->key);     /* memory allocated during initialisation */
    mk->key = (unsigned char *) CRYPTO_MALLOC( mk->keysize, 
                                               sizeof(unsigned char));
    if (NULL == mk->key) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error allocating memory for key!\n");
        #endif

        return result;
    }
    /* key has now been allocated memory */

    /* read keysize + 1 bytes from the file: if we actually read keysize + 1
     * bytes, it means there is a key mismatch. */
    fresult = fread(tmp_key, sizeof *tmp_key, keysize + 1, kf);

    /* two conditions to detect key size mismatches:
     *  1. fresult != 1: because we are trying to read keysize + 1 chars,
     *  fread() will return a 0 if it couldn't read enough characters.
     *  2. with a non-zero fresult, we need to actually check the number
     *  of bytes copied into tmp_key to make sure they match.
     */
    if (keysize != fresult) {
        #ifdef DBEUG
        fprintf(stderr, "[!] key size mismatch in file %s: ", filename);
        fprintf(stderr, "expected %u bytes, actually read %u bytes!\n",
                (unsigned int) keysize, (unsigned int) fresult);
        #endif

        /* first step is to zeroise the tmp_key */
        gcry_create_nonce(tmp_key, keysize + 1);
        gcry_free(tmp_key);

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

        else {
            return SIZE_MISMATCH;
        }
    } /* end read size check */
    
    /* at this point, the key was loaded without error */

    /* copy tmp_key into mk->key and wipe the temp key */
    strncpy((char *) mk->key, (char *) tmp_key, mk->keysize);
    gcry_create_nonce(tmp_key, mk->keysize);
    gcry_free(tmp_key);


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
    char mode[1] = "w";
    
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
    kf = fopen(filename, "w+");
    if ((NULL == kf) || (0 != ferror(kf))) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error opening %s for write!\n", filename);
        perror("fopen");
        #endif

        return result;
    } /* end fopen error checking */

    /* write key to file and check the appropriate number of bytes were 
     * written into the file */
    fresult = fwrite(mk->key, sizeof mk->key, mk->keysize, kf);
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

crypto_key_return_t crypto_zerokey( metakey_t mk ) {
    crypto_key_return_t result = KEY_FAILURE;
    size_t i = 0;

    if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] crypto library not initialised!\n");
        #endif

        return LIB_NOT_INIT;
    }

    if (! 1 == mk->initialised ) {
        #ifdef DEBUG
        fprintf(stderr, "[!] key not initialised!\n");
        #endif

        return KEY_NOT_INIT;
    }

    gcry_create_nonce(mk->key, mk->keysize);
    for (i = 0; i < mk->keysize; ++i) {
        mk->key[i] = '\x00';
    }

    result = KEY_SUCCESS;

    return result;
}   /* end crypto_zerokey */


crypto_key_return_t crypto_zerokeystore( ) {
    crypto_key_return_t result = KEY_FAILURE;

    return result;
} /* end crypto_zerokeystore */


/* auto key generation functions - all are one line */
void set_autogen( ) {
    generate_keys = 1;
}

void unset_autogen( ) {
    generate_keys = 0;
}

int crypto_autogen_status( ) {
    return generate_keys;
}
/* end auto key generation functions */


crypto_key_return_t crypto_wipe_keyfile(const char *filename, int passes) {
    crypto_key_return_t result = KEY_FAILURE;

    return result;
}

