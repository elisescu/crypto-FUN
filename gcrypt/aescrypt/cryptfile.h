/*
 * cryptfile.h
 * Kyle Isom <coder@kyleisom.net>
 *
 * function declarations and defines for cryptfile.c
 */

#ifndef __CRYPTFILE_H
#define __CRYPTFILE_H


#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <gcrypt.h>



int crypto_encrypt_file( FILE *inf, FILE *outf );   /* encrypt inf and output
                                                     * as outf. */

#endif
