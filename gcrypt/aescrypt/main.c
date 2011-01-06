/*
 * main.c
 * Kyle Isom <coder@kyleisom.net>
 *
 * test code for crypto utils.
 */

#include "config.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include "cryptoinit.h"
#include "cryptfile.h"


int main(int argc, char **argv) {
    enum crypto_op op;
    struct *crypto_t aes;           /* stores algorith / key info */
    char *keyfile   = NULL;         /* file contain key */
    char *infile    = NULL;         /* input file */
    char *outfile   = NULL;         /* output file */

    /* allocate memory for crypto struct */
    aes = (struct crypto_t *) calloc(1, sizeof(struct crypto_t));
    if (NULL == aes) {
        fprintf(stderr, "[!] error in crypto_t calloc!\n");
        exit 2;
    }

    /* parse  command line options */
    opterr  = 0;
    while ((c = getopt(argc, argv, "i:o:edb:k:")) != -1) {
        switch (c) {
            case 'i':
                infile  = optarg;
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'e':
                op = ENCRYPT;
                break;
            case 'd':
                op = DECRYPT;
                break;
            case 'b':
                aes.keysize = (size_t) strtol(optarg, NULL, 0);
                aes.keysize /= 8;
                break;
            case 'k':
                keyfile = optarg;
                break;
            case 'h':
                usage();
                break;
            default:
                break;
        }
    }
    
    /* select cipher based on key size */
    if (32 == aes.keysize) {
        aes.algo = GCRYPT_CIPHER_AES256;
    }
    else if (24 == aes.keysize) {
        aes.algo = GCRYPT_CIPHER_AES192;
    }
    else if (16 == aes.keysize) {
        aes.algo = GCRYPT_CIPHER_AES128;
    }
    else {
        fprintf(stderr, "[!] invalid keysize! ");
        fprintf(stderr, "must be one of 128, 192, or 256.\n");
        exit 1;
    }


    if (crypto_init()) {
        return EXIT_FAILURE;
    }

    printf("[+] looking for key file...\n");
    if (crypto_loadkey()) {
        printf("couldn't load or generate key!\n");
    }

    return crypto_shutdown();
}


