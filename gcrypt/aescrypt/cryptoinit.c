/**************************************************************************
 * cryptoinit.c                                                           *
 * 4096R/B7B720D6 "Kyle Isom <coder@kyleisom.net>"                        *
 * 2011-01-06                                                             *
 *                                                                        *
 * cryptographic initialisation functions, including key generation       *
 **************************************************************************/

#include "cryptoinit.h"
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>

/*************************/
/* crypto initialisation */
/*************************/
keystore_t crypto_init( ) {
    size_t i = 0;           /* loop index */
    keystore = NULL;

#ifdef DBEUG
    printf("[+] initialising gcrypt...\n");
#endif

    if (! gcry_check_version(GCRYPT_MIN_VERSION)) {
#ifdef DEBUG
        fprintf(stderr, "[!] version mismatch. the minimum version is %s\n", 
                GCRYPT_MIN_VERSION);
#endif
        return NULL;
    }

    /* suspend secure memory warnings - if secure memory is to be used,
     * it will be re-enabled later. */
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);


    /************************
     * set up secure memory *
     ************************/
#if SECURE_MEM != 0

#ifdef DEBUG
    printf("[+] setting up secure memory...\n");
#endif

    /* place the random pool in secure memory */
    gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);

    /* allocate secure memory */
    gcry_control(GCRYCTL_INIT_SECMEM, SECURE_MEM);

    /* resume secure memory warnings */
    gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

#endif

    /* signal initialization complete  - library ready for use */
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

#ifdef DEBUG
    printf("[+] finished library initialisation...\n");
    printf("[+] setting up keystore...\n");
#endif

    /* allocate memory to keystore */
    keystore    = CRYPTO_MALLOC( 1, sizeof *keystore);
    keystore->store = CRYPTO_MALLOC( KEYSTORE_SIZE,
            sizeof(metakey_t));
    keystore->size  = 0;

    for (i = 0; i < KEYSTORE_SIZE; ++i) {
        size_t keysize = 32;

#ifdef DEBUG
        printf("allocating space for key #%u with size %u bytes...\n", 
                i, keysize);
#endif

        keystore->store[i] = CRYPTO_MALLOC(1, sizeof(struct metakey));
        keystore->store[i]->key = CRYPTO_MALLOC( keysize, 
                                  sizeof keystore->store[i]->key);
        keystore->store[i]->initialised = 1;

        keystore->store[i]->sm = SECURE_MEM != 0;
    }

    return keystore;
}


/***********************************************************/
/* close down crypto library and destroy any secure memory */
/***********************************************************/
crypto_return_t crypto_shutdown( ) {
    size_t i = 0;

    if (! gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
#ifdef DEBUG
        fprintf(stderr, "[!] crypto library not initialised!\n");
#endif

        return EXIT_FAILURE;
    }

#ifdef DEBUG
    printf("[+] shutting down crypto system...\n");
#endif

    /* destroy keys */
    for (i = 0; i < KEYSTORE_SIZE; ++i) {
#ifdef DEBUG
        printf("[+] wiping key %d...\n", i);
#endif

        if (! keystore->store[i]->initialised) {
#ifdef DEBUG
            printf("[+] key not initalised, skipping...\n");
#endif

            continue;
        }

        gcry_create_nonce(keystore->store[i]->key, 
                keystore->store[i]->keysize);

        gcry_free(keystore->store[i]);
        keystore->store[i] = NULL;
    }

    gcry_free( keystore->store );
    keystore->store = NULL;
    gcry_free( keystore );

    /* if secure memory is used, zeroise and shutdown secure memory */
#if SECURE_MEM != 0
    gcry_control(GCRYCTL_TERM_SECMEM);
    gcry_control(GCRYCTL_DISABLE_SECMEM);
#endif

    return EXIT_SUCCESS;
}
