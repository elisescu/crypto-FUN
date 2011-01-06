/*
 * cryptfile.c
 * Kyle Isom <coder@kyleisom.net>
 *
 * provides functions to encrypt and decrypt files
 */

#include "cryptfile.h"

int crypto_encrypt_file( FILE *inf, FILE *outf ) { 
    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        printf("crypto library has not been initialised!\n");
        return EXIT_FAILURE;
    }   


    return EXIT_SUCCESS;

}

