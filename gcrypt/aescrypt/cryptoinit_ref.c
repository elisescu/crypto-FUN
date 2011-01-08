/*
 * cryptoinit.c
 * Kyle Isom <coder@kyleisom.net>
 * 2011-01-06
 *
 * cryptographic initialisation functions, including key generation 
 */

#include "cryptoinit.h"

int crypto_init( ) {
    #ifdef DBEUG
    printf("[+] initialising gcrypt...\n");
    #endif

    if (! gcry_check_version(GCRYPT_MIN_VERSION)) {
        #ifdef DEBUG
        fprintf("[!] version mismatch. the minimum version is %s\n", 
                GCRYPT_MIN_VERSION);
        #endif
        return EXIT_FAILURE;
    }

    /* suspend secure memory warnings - if secure memory is to be used,
     * it will be re-enabled later. */
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARNING);

    #ifdef SECURE_MEM

    /* place the random pool in secure memory */
    gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);

    /* allocate secure memory */
    gcry_control(GCRYCTL_INIT_SECMEM, SECURE_MEM, 0);

    /* resume secure memory warnings */
    gcry_control(GCRYCTL_RESUME_SECMEM_WARNING);
    #endif

    /* signal initialization complete  - library ready for use */
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    #ifdef DEBUG
    printf("[+] finished initialisation...\n");
    #endif

    return EXIT_SUCCESS;
}

int crypto_shutdown( struct crypto_t **keyring ) {
    #ifdef DEBUG
    printf("[+] shutting down crypto system...\n");
    #endif

    struct crypto_t *key = keyring;

    while (NULL != key) {
        /* free the key */
        gcry_free( key->key );
        key->key = NULL;

        free(key);
        key = NULL;

        key++;
    }

    /* disable secmem - has no effect if it's not being used */
    gcry_control(GCRYCTL_TERM_SECMEM);
    gcry_control(GCRYCTL_DISABLE_SECMEM);

    #ifdef DEBUG
    printf("[+] crypto system shutdown!\n");
    #endif

    return EXIT_SUCCESS;
}

int crypto_genkey( struct crypto_t *keydata ) {
    #ifdef DEBUG
    printf("[+] generating key...\n");
    #endif

    /* make sure the key doesn't have data in it */
    if (! NULL== keydata->key) {
        gcry_free(keydata->key);
        keydata->key = NULL;
    }

    #ifdef SECURE_MEM
    /* if we're using secure mem, get the key from there */
    keydata->key = (char *) gcry_random_bytes_secure(
                                keydata->keysize * sizeof(char),
                                RANDOM_STRENGTH);
    #else
    /* fill the key with keysize random bytes */
    keyinfo->key = (char *) gcry_random_bytes(
                                keydata->keysize * sizeof(char),
                                RANDOM_STRENGTH);
    #endif

    /* did we make it, Jim!? */
    if (NULL == keydata->key) {
        #ifdef DEBUG
        fprintf(stderr, "[!] error generating key!\n");
        #endif

        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

/* TODO: clean up this section to remove code duplication */
int crypto_loadkeyfile( const char *keyfile, struct crypto_t *keydata ) {
    /* if a NULL filename was passed in, the correct behaviour is to
     * die, as the user has no way of storing the key */
    if (NULL == keyfile) {
        #ifdef DEBUG
        fprintf(stderr, "[!] invalid keyfile specified!\n");
        #endif

        return EXIT_FAILURE;
    }

    #ifdef DEBUG
    printf("[+] attempting to load key from file %s...\n", keyfile);
    #endif

    size_t read_sz = 0;
    FILE *kp = fopen(keyfile, "r");

    /* make sure the file was opened before trying to read from it */
    if (ferror(kp)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] could not load key from %s!\n", keyfile);
        perror("fopen");
        #endif

        return EXIT_FAILURE;
    }

    /* use MAX_KEY_SIZE + 1 to detect a key size greater than the 
     * maximum allowed... */
    read_sz = fread(keydata->key, sizeof(char), MAX_KEY_SIZE + 1, kp);
    
    /* make sure we read enough bytes from the file */
    if (! keydata->keysize == read_sz ) {

        #ifdef DEBUG
        fprintf(stderr, "[!] wrong size key for cipher!\n");
        fprintf(stderr, "\t(expected %u, read %u bytes)\n",
                keydata->keysize, read_sz);
        #endif

        /* if we failed to read the key, generate a new key */
        if (crypto_genkey(keydata)) {
            #ifdef DEBUG
            fprintf(stderr, "[!] fatal error getting a key!\n");
            #endif

            /* this is a non-recoverable error, so we exit */
            exit(2);
        }

        /* TODO: close before dumping */
        else {
            if ( fclose(kp) ) {
                #ifdef DEBUG
                fprintf(stderr, "[!] error closing key file!\n");
            crypto_dumpkey(keyfile, keydata);
            return EXIT_SUCCESS;
        }
    }

    else {
        if (! 0 == fclose(kp)) {
            /* key was loaded, but the keyfile is in an inconsistent 
             * state. this is bad... */
            #ifdef DEBUG
            fprintf(stderr, "[!] key was loaded, but encountered an ",
                    "error closing the keyfile!\n");
            perror("fclose");
            #endif

            return EXIT_FAILURE;
        }
    
        else {
            #ifdef DEBUG
            printf("[+] key successfully loaded!");
            #endif

            return EXIT_SUCCESS;
        }
    }
}

int crypto_dumpkey( const char *keyfile, struct crypto_t *keydata ) {
    /* if a NULL keyfile was passed, we can't very well write to that,
     * now can we? */
    if (NULL == keyfile) {
        #ifdef DEBUG
        fprintf(stderr, "[!] can't write to a NULL keyfile!\n");
        return EXIT_FAILURE;
    }

    #ifdef DEBUG
    printf("[+] attempting to write key to keyfile %s...\n", keyfile);
    #endif

    size_t write_sz = 0;
    FILE *kp = fopen(keyfile, "w");

    /* sanity check to make sure the file was opened successfully */
    if ( ferror(kp) ) {
        #ifdef DBEUG
        fprintf(stderr, "[!] error opening %s for write!\n", keyfile);
        #endif

        return EXIT_FAILURE;
    }

    /* write out the key to the keyfile */
    write_sz = fwrite(keydata->key, sizeof(char), keydata->keysize, kp);

    /* ensure the expected number of bytes were written */
    if (keydata->keysize != write_sz) {
        #ifdef DBEUG
        fprintf(stderr, "[!] wrote an invalid number of bytes to %s!\n", 
                keyfile);
        fprintf(stderr, "\t(expected %u, wrote %u bytes)\n", 
                keydata->keysize, write_sz);
        #endif

        return EXIT_FAILURE;
    }

    #ifdef DEBUG
    printf("[+] successfully wrote key!\n");
    #endif

    /* if the keyfile can't be closed, it is in an inconsistent state;
     * in theory an attacker could write to it */
    if (! 0 == fclose(kp)) {
        #ifdef DEBUG
        fprintf(stderr, "[!] key successfully written but could not close ",
                "keyfile!\n");
        perror("fclose");
        #endif

        return EXIT_FAILURE;
    }

    else {
        #ifdef DEBUG
        printf("[+] key successfully written to %s!\n");
        #endif

        return EXIT_SUCCESS;
    }
}

    
