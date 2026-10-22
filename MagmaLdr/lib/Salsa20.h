#pragma once
#include <Windows.h>
#include <stdint.h>

#define STORE32L(x, y)                                                                     \
  do { (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD32L(x, y)                            \
  do { x = ((ULONG32)((y)[3] & 255)<<24) | \
           ((ULONG32)((y)[2] & 255)<<16) | \
           ((ULONG32)((y)[1] & 255)<<8)  | \
           ((ULONG32)((y)[0] & 255)); } while(0)

#define STORE64L(x, y)                                                                     \
  do { (y)[7] = (unsigned char)(((x)>>56)&255); (y)[6] = (unsigned char)(((x)>>48)&255);   \
       (y)[5] = (unsigned char)(((x)>>40)&255); (y)[4] = (unsigned char)(((x)>>32)&255);   \
       (y)[3] = (unsigned char)(((x)>>24)&255); (y)[2] = (unsigned char)(((x)>>16)&255);   \
       (y)[1] = (unsigned char)(((x)>>8)&255); (y)[0] = (unsigned char)((x)&255); } while(0)

#define LOAD64L(x, y)                                                       \
  do { x = (((ULONG64)((y)[7] & 255))<<56)|(((ULONG64)((y)[6] & 255))<<48)| \
           (((ULONG64)((y)[5] & 255))<<40)|(((ULONG64)((y)[4] & 255))<<32)| \
           (((ULONG64)((y)[3] & 255))<<24)|(((ULONG64)((y)[2] & 255))<<16)| \
           (((ULONG64)((y)[1] & 255))<<8)|(((ULONG64)((y)[0] & 255))); } while(0)

#define STORE32H(x, y)                                                                     \
  do { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); } while(0)

#define LOAD32H(x, y)                            \
  do { x = ((ULONG32)((y)[0] & 255)<<24) | \
           ((ULONG32)((y)[1] & 255)<<16) | \
           ((ULONG32)((y)[2] & 255)<<8)  | \
           ((ULONG32)((y)[3] & 255)); } while(0)

#define STORE64H(x, y)                                                                     \
do { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); } while(0)

#define LOAD64H(x, y)                                                      \
do { x = (((ULONG64)((y)[0] & 255))<<56)|(((ULONG64)((y)[1] & 255))<<48) | \
         (((ULONG64)((y)[2] & 255))<<40)|(((ULONG64)((y)[3] & 255))<<32) | \
         (((ULONG64)((y)[4] & 255))<<24)|(((ULONG64)((y)[5] & 255))<<16) | \
         (((ULONG64)((y)[6] & 255))<<8)|(((ULONG64)((y)[7] & 255))); } while(0)


#ifndef MAX
#define MAX(x, y) ( ((x)>(y))?(x):(y) )
#endif

#ifndef MIN
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

#define LTC_ARGCHK( x ) if ( ! ( x ) ) return CRYPT_ERROR;

enum {
	CRYPT_OK = 0,             /* Result OK */
	CRYPT_ERROR,            /* Generic Error */
	CRYPT_NOP,              /* Not a failure but no operation was performed */

	CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
	CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
	CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

	CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
	CRYPT_INVALID_PACKET,   /* Invalid input packet given */

	CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
	CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

	CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
	CRYPT_INVALID_HASH,     /* Invalid hash specified */
	CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

	CRYPT_MEM,              /* Out of memory */

	CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
	CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

	CRYPT_INVALID_ARG,      /* Generic invalid argument */
	CRYPT_FILE_NOTFOUND,    /* File Not Found */

	CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */

	CRYPT_OVERFLOW,         /* An overflow of a value was detected/prevented */

	CRYPT_PK_ASN1_ERROR,    /* An error occurred while en- or decoding ASN.1 data */

	CRYPT_INPUT_TOO_LONG,   /* The input was longer than expected. */

	CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

	CRYPT_INVALID_PRIME_SIZE, /* Invalid size of prime requested */
	CRYPT_PK_INVALID_PADDING, /* Invalid padding on input */

	CRYPT_HASH_OVERFLOW,     /* Hash applied to too many bits */
	CRYPT_PW_CTX_MISSING,    /* Password context to decrypt key file is missing */
	CRYPT_UNKNOWN_PEM,       /* The PEM header was not recognized */

	/* Here only follows the number of error codes.
	 * This will never be returned and shall always be at the end of the enum. */
	CRYPT_ERR_NUM
};

#define ulong32 ULONG
typedef unsigned long long ulong64;

typedef struct {
	ulong32 input[16];
	unsigned char kstream[64];
	unsigned long ksleft;
	unsigned long ivlen;
	int rounds;
} salsa20_state;

int salsa20_done(salsa20_state* st);

int salsa20_ivctr64(salsa20_state* st, const unsigned char* iv, unsigned long ivlen, ulong64 counter);

int salsa20_setup(salsa20_state* st, const unsigned char* key, unsigned long keylen, int rounds);

int salsa20_crypt(salsa20_state* st, const unsigned char* in, unsigned long inlen, unsigned char* out);