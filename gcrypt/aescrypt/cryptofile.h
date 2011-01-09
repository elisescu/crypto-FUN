/**************************************************************************
 * cryptofile.h                                                           *
 * 4096R/B7B720D6 "Kyle Isom <coder@kyleisom.net>"                        *
 * 2011-01-08                                                             *
 *                                                                        *
 * defines crypto functions on files                                      *
 **************************************************************************/

#ifndef __CRYPTOFILE_H
#define __CRYPTOFILE_H

#include <stdlib.h>

#include "config.h"
#include "crypto.h"
#include "metakey.h"

/* crypto_wipe_file
 */
crypto_key_return_t crypto_wipe_file( const char *, size_t );




#endif
