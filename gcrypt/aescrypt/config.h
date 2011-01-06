/*
 * config.h
 * Kyle Isom <coder@kyleisom.net>
 *
 * configuration options for aescrypt
 */
_
/* use secure memory */
#define 	SECURE_MEM		1

/* don't pull in unnecessary gcrypt functions */
#define		GCRYPT_NO_MPI_MACROS	1
#define		GRYPT_NO_DEPRECATED	1

