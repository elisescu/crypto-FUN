/**************************************************************************
 * cryptofile.c                                                           *
 * 4096/B7B720D6 "Kyle Isom <coder@kylesiom.net>"                         *
 * 2011-01-08                                                             *
 *                                                                        *
 * cryptographic file functions                                           *
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <gcrypt.h>

#include "config.h"
#include "crypto.h"
#include "cryptofile.h"

crypto_key_return_t crypto_wipe_file(const char *filename, size_t passes) {
    crypto_key_return_t result = KEY_FAILURE;
    FILE *kf = NULL;
    struct stat kf_stat;
    unsigned char *rdata = NULL;    /* random data buffer */
    size_t file_size = 0;
    size_t wipe_buf_size = 0;   /* amount of random chars to gen each round */
    size_t rounds    = 1;       /* needed to handle secure mem */
    size_t i = 0, j = 0;        /* loop counters */

    /* use stat to get file size */
#ifdef DEBUG
    printf("[+] stat'ing %s...\n", filename);
#endif 
    if (-1 == stat(filename, &kf_stat)) {
#ifdef DEBUG
        perror("[!] stat");
#endif
        return result;
    }
#ifdef DEBUG
    printf("[+] stat complete!\n");
#endif

    /* compute number of rounds and the size of the random data buffer
     * that will be written to the file */
    file_size = (size_t) kf_stat.st_size;
#if SECURE_MEM != 0
    rounds = (file_size / (SECURE_MEM / 5)) + 1;
    wipe_buf_size = (SECURE_MEM / 5);
#else
    wipe_buf_size = file_size;
#endif

    /* for debugging purposes, print out some wipe data */
#ifdef DEBUG
    printf("[+] wipe data:\n");
    printf("    wipe size: %u\n    passes: %u\n    rounds: %u\n", 
            (unsigned int) wipe_buf_size, (unsigned int) passes,
            (unsigned int) rounds);
#endif

    /* top-level loop to write to the file passes number of times */
    for (i = 0; i < passes; ++i) {
#ifdef DEBUG
        printf("[+] wipe pass number %u\n", (unsigned int) i);
#endif

        kf = fopen(filename, "w");

        /* error checking */
        if (NULL == kf) {
#ifdef DEBUG
            fprintf(stderr, "[!] %s does not exist!\n", filename);
#endif

            return result;
        } else if (0 != ferror(kf)) {
#ifdef DEBUG
            fprintf(stderr, "[!] encountered an error opening %s!\n", 
                    filename);
            perror("fopen");
#endif

            return result;
        }

        /* inner loop to write the buffer to the file */
        for (j = 0; j < rounds; ++j) {
            size_t written = 0;
#ifdef DEBUG
            printf("\twipe round %u\n", (unsigned int) j);
#endif

            rdata = CRYPTO_MALLOC( wipe_buf_size, sizeof rdata );
            gcry_create_nonce(rdata, wipe_buf_size);

            /* write and check for errors */
            written = fwrite(rdata, sizeof *rdata, wipe_buf_size, kf);

            /* sanity check to make sure we wrote as many bytes as we 
             * wanted to */
            if (written != wipe_buf_size) {
#ifdef DEBUG
                fprintf(stderr, "[!] did not write expected number of ");
                fprintf(stderr, "bytes (expected %u bytes, wrote %u bytes",
                        (unsigned int) wipe_buf_size, (unsigned int) written);
                fprintf(stderr, "\nto file: %s\n", filename);
#endif
                result = INCONSISTENT_STATE;

                return result;
            }

            gcry_free(rdata);
        } /* end of wiping round */

        /* close and check for errors */
        if (0 != fclose(kf)) {
#ifdef DEBUG
            fprintf(stderr, "[!] error encountered closing %s!\n", filename);
            perror("fclose");
#endif

            return result;
        }

    } /* end of write pass */

    /* finally remove the file from the file system */
    if (0 != unlink(filename)) {
#ifdef DEBUG
        fprintf(stderr, "error unlinking file!\n");
#endif
    } else {
        result = KEY_SUCCESS;   /* making it this far means wiping 
                                 * was successful */
    }

    return result;
}

