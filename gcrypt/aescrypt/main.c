/*
 * main.c
 * Kyle Isom <coder@kyleisom.net>
 *
 * test code for crypto utils.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include "cryptinit.h"
#include "cryptfile.h"


int main(int argc, char *argv[]) {
    char *key;
    if (crypto_init()) {
        return EXIT_FAILURE;
    }

    printf("[+] looking for key file...\n");
    if (crypto_loadkey()) {
        printf("couldn't load or generate key!\n");
    }

    return crypto_shutdown();
}

