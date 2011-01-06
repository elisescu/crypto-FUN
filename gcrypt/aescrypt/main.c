/*
 * main.c
 * Kyle Isom <coder@kyleisom.net>
 *
 * test code for crypto utils.
 */

#include <stdio.h>
#include <stdlib.h>
#include "secure_init.h"
#include "cryptfile.h"

char *key;

int main(int argc, char *argv[]) {
    if (crypto_init()) {
        return EXIT_FAILURE;
    }

    printf("[+] looking for key file...\n");
    if (crypto_loadkey()) {
        printf("couldn't load or generate key!\n");
    }

    return crypto_shutdown();
}

