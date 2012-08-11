
#ifndef PORTABLE_C__
#define PORTABLE_C__

#ifdef _MSC_VER
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#define LL(v)   (v##i64)
#else
#include <stdint.h>
#define LL(v)   (v##ULL)
#endif

/*
 * Whirlpool-specific definitions.
 */

#define DIGESTBYTES 64
#define DIGESTBITS  (8*DIGESTBYTES) /* 512 */

#define WBLOCKBYTES 64
#define WBLOCKBITS  (8*WBLOCKBYTES) /* 512 */

#define LENGTHBYTES 32
#define LENGTHBITS  (8*LENGTHBYTES) /* 256 */

typedef struct NESSIEstruct {
	uint8_t  bitLength[LENGTHBYTES]; /* global number of hashed bits (256-bit counter) */
	uint8_t  buffer[WBLOCKBYTES];	/* buffer of data to hash */
	uint32_t bufferBits;		        /* current number of bits on the buffer */
	uint32_t bufferPos;		        /* current (possibly incomplete) byte slot on the buffer */
	uint64_t hash[DIGESTBYTES/8];    /* the hashing state */
} NESSIEstruct;

#endif   /* PORTABLE_C__ */

