/**************************************************************************
 * debug.h                                                                *
 * 4096/B7B720D6 "Kyle Isom <coder@kyleisom.net>"                         *
 * 2011-01-10                                                             *
 *                                                                        *
 * debug macros                                                           *
 **************************************************************************/

#ifndef __DEBUG_H
#define __DEBUG_H

#include "config.h"

#ifdef DEBUG
#define LOG(a)                    printf((a))
#define TRACEOUT(a)               fprintf(stderr, (a))
#define TRACEOUT_1(a, b)          fprintf(stderr, (a), (b))

#else
#define TRACEOUT(a)                {} 
#define TRACEOUT_1(a, b)           {}

#endif /* end debug macros */

#endif  /* end header guard */
