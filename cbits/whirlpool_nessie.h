
#ifndef PORTABLE_C__
#define PORTABLE_C__

#include <limits.h>

/* Definition of minimum-width integer types
 * 
 * u8   -> unsigned integer type, at least 8 bits, equivalent to unsigned char
 * u16  -> unsigned integer type, at least 16 bits
 * u32  -> unsigned integer type, at least 32 bits
 *
 * s8, s16, s32  -> signed counterparts of u8, u16, u32
 */

typedef signed char s8;
typedef unsigned char u8;

#if UINT_MAX >= 4294967295UL

typedef signed short s16;
typedef signed int s32;
typedef unsigned short u16;
typedef unsigned int u32;

#else

typedef signed int s16;
typedef signed long s32;
typedef unsigned int u16;
typedef unsigned long u32;

#endif

#ifdef _MSC_VER
typedef unsigned __int64 u64;
typedef signed __int64 s64;
#define LL(v)   (v##i64)
#else  /* !_MSC_VER */
typedef unsigned long long u64;
typedef signed long long s64;
#define LL(v)   (v##ULL)
#endif /* ?_MSC_VER */

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
	u8  bitLength[LENGTHBYTES]; /* global number of hashed bits (256-bit counter) */
	u8  buffer[WBLOCKBYTES];	/* buffer of data to hash */
	int bufferBits;		        /* current number of bits on the buffer */
	int bufferPos;		        /* current (possibly incomplete) byte slot on the buffer */
	u64 hash[DIGESTBYTES/8];    /* the hashing state */
} NESSIEstruct;

#endif   /* PORTABLE_C__ */

