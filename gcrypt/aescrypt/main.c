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

#include "cryptinit.h"
#include "cryptfile.h"


int main(int argc, char **argv) {
    char *key;
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
        case 'i':
            
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

