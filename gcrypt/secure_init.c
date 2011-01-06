/*
 * secure_init.c
 * Kyle Isom <coder@kyleisom.net>
 *
 * gcrypt init code and tests.
 *
 */

#include "secure_init.h"


int crypto_init( ) {
    printf("[+] performing basic initialisation...\n");
    printf("[+] ...\n");
    if (!gcry_check_version(NULL)) {
        printf("could not initialize crypto libraries!\n");
        exit(2);
    }

    /* suspend warnings about secure memory - still have more initialisation 
     * to do before enabling secure memory.
     */
    printf("[+] suspend secure memory warnings...\n");
    gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);

    /* set up secure PRNG */
    printf("[+] initialise secure PRNG...\n");
    gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);
    
    /* initialise secure memory */
    printf("[+] initialise secure memory...\n");
    gcry_control(GCRYCTL_INIT_SECMEM, SECMEM_SZ, 0);

    /* initialisation complete */
    printf("[+] finished!\n");
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);


    return EXIT_SUCCESS;
}





int crypto_shutdown( char *key ) {
    if (! gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) {
        return EXIT_SUCCESS;
    }
    
    /* reclaim the key */
    printf("[+] freeing key...\n");
    gcry_free(key);
    key = NULL;

    /* tell gcrypt to zerioise and disable secure memory */
    printf("[+] zeroising secure memory...\n");
    gcry_control(GCRYCTL_TERM_SECMEM); 
    gcry_control(GCRYCTL_DISABLE_SECMEM);

    return EXIT_SUCCESS;
}



int crypto_genkey( char *key ) {
    /* sanity check to ensure gcrypt has been initialised */
    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        printf("crypto library has not been initialised!\n");
        return EXIT_FAILURE;
    }
    
    printf("[+] generating key..."); 
    fflush(stdout);
    /* generate key in secure memory */
    key = (char *) gcry_random_bytes_secure(KEYSIZE * sizeof(char), 
                                            GCRY_VERY_STRONG_RANDOM);
    if (NULL == key) {
        printf("\t\t\t\tFAILED!\n");
        return EXIT_FAILURE;
    }

    printf("\t\t\t\tOK!\n");
    return EXIT_SUCCESS;
}




int crypto_loadkey( char *key ) {
    /* determine if a keyfile is present */
    if (-1 == access( KEYFILE, R_OK )) {
        printf("[+] key file not found (%s not present), generating key...\n",
               KEYFILE);
        /* if no keyfile, generate a new key */
        if (! crypto_genkey(key) ) {
            return EXIT_FAILURE;
        }
        else {
            return EXIT_SUCCESS;
        }
    } 
    else {
        /* allocate secure memory for key */
        char *key   = gcry_calloc_secure(KEYSIZE, sizeof(char));
        if (NULL == key) {
            printf("error allocating secure memory for key!\n");
            return EXIT_FAILURE;
        }

        /* open key file */
        FILE *kd    = fopen( KEYFILE, "r" );

        if (ferror(kd)) {
            printf("error opening file!\n");
            return EXIT_FAILURE;
        }

        /* attempt to read the appropriate number of bytes into the key */
        if (KEYSIZE < fread( key, sizeof(char), KEYSIZE, kd )) {
            printf("key size mismatch, generating new key...\n");
            if (! crypto_genkey(key) ) {
                return EXIT_FAILURE;
            }
        }
        printf("[+] read %d bytes into key...\n", KEYSIZE);

        if (fclose(kd)) {
            printf("error release key file!\n");
            return EXIT_FAILURE;
        }

    }

    return EXIT_SUCCESS;
}


