/************************************************************************
 * init_test.c                                                          *
 * 4096R/B7B720D6 "Kyle Isom <coder@kyleisom.net>                       *
 *                                                                      *
 * test initialisation / shutdown code                                  *
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "cryptoinit.h"
#include "metakey.h"

#define KEYFILE             "aes128.key"

extern keystore_t keystore;

int main(int argc, char **argv ) {
    /* return values for the crypto functions */
    crypto_return_t init_result     = CRYPTO_FAILURE;
    crypto_key_return_t key_result  = KEY_FAILURE;
    size_t keysize                  = 16;   /* AES128 */
    int loadkey                     = 0;

    /* check for load / dump operation */
    if (2 == argc) {
        if ( (1 == strlen(argv[1])) && (0 == strncmp(argv[1], "l", 1))) {
            loadkey = 1;
            printf("[+] %s: will load key from file %s...\n", argv[0], 
                    KEYFILE);
        }
    }

    /* initialisation returns NULL on failure */
    keystore = crypto_init( );
    if (NULL == keystore) {
        fprintf(stderr, "[!] %s: keystore generation failed!\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("[+] %s: cryptographic libraries initialised...\n", argv[0]);

    if (0 == loadkey) {
        printf("[+] generating a key...\n");
        key_result = crypto_genkey( keystore->store[0], keysize );
        if (KEY_FAILURE == key_result) {
            fprintf(stderr, "[!] %s: key generation failed!\n", argv[0]);
            return EXIT_FAILURE;
        }

        if (KEY_NOT_INIT == key_result) {
            fprintf(stderr, "[!] %s: library not initialised!\n",
                    argv[0]);
            return EXIT_FAILURE;
        }

        printf("[!] %s: key successfully generated!\n", argv[0]);

        key_result = crypto_dumpkey(KEYFILE, keystore->store[0]);
        if (KEY_SUCCESS == key_result) {
            printf("[!] %s: key dumped to %s!\n", argv[0], KEYFILE);
        }
    } /* end key dump handling */

    else {
        key_result = crypto_loadkey(KEYFILE, keystore->store[0], keysize);

        switch (key_result) {
            case KEY_FAILURE:
                fprintf(stderr, "[!] %s: error loading key!\n", KEYFILE);
                break;
            case KEY_SUCCESS:
                fprintf(stderr, "[+] %s: key successfully loaded!\n",
                        argv[0]);
                break;
            case KEYGEN:
                fprintf(stderr, "[!] %s: error reading %s, key was ",
                        argv[0], KEYFILE);
                fprintf(stderr, "generated.\n");
            case SIZE_MISMATCH:
                fprintf(stderr, "[!] %s: the key read was the wrong length",
                        argv[0]);
                break;
            case KEYGEN_ERR:
                fprintf(stderr, "[!] %s: error reading file and error ",
                        argv[0]);
                fprintf(stderr, "generating a new key!\n");
                break;
            case LIB_NOT_INIT:
                fprintf(stderr, "[!] %s: library not initialised!\n", 
                        argv[0]);
                break;
            case INCONSISTENT_STATE:
                fprintf(stderr, "[!] %s: keyfile in an inconsistent state!",
                        argv[0]);
                break;
            default:
                fprintf(stderr, "[!] %s: should not be in default case!\n",
                        argv[0]);
                break;
        }
    } /* end key loading */

    init_result = crypto_shutdown( );

    return init_result;
}

