{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.Hash
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash main module
--
module Crypto.Hash
    (
    -- * Types
      HashAlgorithm(..)
    , HashFunctionBS
    , HashFunctionLBS
    , Context
    , Digest
    -- * Functions
    , digestToByteString
    , digestToHexByteString
    , hash
    , hashlazy
    , hashUpdate
    , hashInitAlg
    -- * hash algorithms
    , MD2(..)
    , MD4(..)
    , MD5(..)
    , SHA1(..)
    , SHA224(..)
    , SHA256(..)
    , SHA384(..)
    , SHA512(..)
    , RIPEMD160(..)
    , Tiger(..)
    , SHA3_224(..)
    , SHA3_256(..)
    , SHA3_384(..)
    , SHA3_512(..)
    , Skein256_224(..)
    , Skein256_256(..)
    , Skein512_224(..)
    , Skein512_256(..)
    , Skein512_384(..)
    , Skein512_512(..)
    , Whirlpool(..)
    -- * MAC algorithms
    , HMAC(..)
    , hmac
    )
    where

import Crypto.Hash.Types
import Crypto.Hash.Utils
import Data.ByteString (ByteString)
import Data.Byteable
import Data.Bits (xor)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD4 as MD4
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA3 as SHA3
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.Tiger as Tiger
import qualified Crypto.Hash.Skein256 as Skein256
import qualified Crypto.Hash.Skein512 as Skein512
import qualified Crypto.Hash.Whirlpool as Whirlpool

-- | Alias to a single pass hash function that operate on a strict bytestring
type HashFunctionBS a = ByteString -> Digest a

-- | Alias to a single pass hash function that operate on a lazy bytestring
type HashFunctionLBS a = L.ByteString -> Digest a

-- | run hashUpdates on one single bytestring and return the updated context.
hashUpdate :: HashAlgorithm a => Context a -> ByteString -> Context a
hashUpdate ctx b = hashUpdates ctx [b]

-- | Hash a strict bytestring into a digest.
hash :: HashAlgorithm a => ByteString -> Digest a
hash bs = hashFinalize $ hashUpdate hashInit bs

-- | Hash a lazy bytestring into a digest.
hashlazy :: HashAlgorithm a => L.ByteString -> Digest a
hashlazy lbs = hashFinalize $ hashUpdates hashInit (L.toChunks lbs)

-- | Return the hexadecimal (base16) bytestring of the digest
digestToHexByteString :: Digest a -> ByteString
digestToHexByteString = toHex . toBytes

#define DEFINE_INSTANCE(NAME, MODULENAME) \
data NAME = NAME deriving Show; \
instance HashAlgorithm NAME where \
    { hashInit = Context c where { (MODULENAME.Ctx c) = MODULENAME.init } \
    ; hashUpdates (Context c) bs = Context nc where { (MODULENAME.Ctx nc) = MODULENAME.updates (MODULENAME.Ctx c) bs } \
    ; hashFinalize (Context c) = Digest $ MODULENAME.finalize (MODULENAME.Ctx c) \
    ; digestFromByteString bs = if B.length bs == len then (Just $ Digest bs) else Nothing where { len = B.length (MODULENAME.finalize MODULENAME.init) } \
    };

#define DEFINE_INSTANCE_LEN(NAME, MODULENAME, LEN) \
data NAME = NAME deriving Show; \
instance HashAlgorithm NAME where \
    { hashInit = Context c where { (MODULENAME.Ctx c) = MODULENAME.init LEN } \
    ; hashUpdates (Context c) bs = Context nc where { (MODULENAME.Ctx nc) = MODULENAME.updates (MODULENAME.Ctx c) bs } \
    ; hashFinalize (Context c) = Digest $ MODULENAME.finalize (MODULENAME.Ctx c) \
    ; digestFromByteString bs = if B.length bs == len then (Just $ Digest bs) else Nothing where { len = B.length (MODULENAME.finalize (MODULENAME.init LEN)) } \
    };

DEFINE_INSTANCE(MD2, MD2)
DEFINE_INSTANCE(MD4, MD4)
DEFINE_INSTANCE(MD5, MD5)
DEFINE_INSTANCE(SHA1, SHA1)
DEFINE_INSTANCE(SHA224, SHA224)
DEFINE_INSTANCE(SHA256, SHA256)
DEFINE_INSTANCE(SHA384, SHA384)
DEFINE_INSTANCE(SHA512, SHA512)

DEFINE_INSTANCE(RIPEMD160, RIPEMD160)
DEFINE_INSTANCE(Whirlpool, Whirlpool)
DEFINE_INSTANCE(Tiger, Tiger)

DEFINE_INSTANCE_LEN(SHA3_224, SHA3, 224)
DEFINE_INSTANCE_LEN(SHA3_256, SHA3, 256)
DEFINE_INSTANCE_LEN(SHA3_384, SHA3, 384)
DEFINE_INSTANCE_LEN(SHA3_512, SHA3, 512)

DEFINE_INSTANCE_LEN(Skein256_224, Skein256, 224)
DEFINE_INSTANCE_LEN(Skein256_256, Skein256, 256)

DEFINE_INSTANCE_LEN(Skein512_224, Skein512, 224)
DEFINE_INSTANCE_LEN(Skein512_256, Skein512, 256)
DEFINE_INSTANCE_LEN(Skein512_384, Skein512, 384)
DEFINE_INSTANCE_LEN(Skein512_512, Skein512, 512)

-- | Initialize a new context for a specified hash algorithm
hashInitAlg :: HashAlgorithm alg => alg -> Context alg
hashInitAlg _ = hashInit

-- | Represent an HMAC that is a phantom type with the hash used to produce the mac.
--
-- The Eq instance is constant time.
data HMAC a = HMAC ByteString

instance Byteable (HMAC a) where
    toBytes (HMAC b) = b

instance Eq (HMAC a) where
    (HMAC b1) == (HMAC b2) = constEqBytes b1 b2

-- | compute a MAC using the supplied hashing function
hmac :: HashFunctionBS a -- ^ Hash function to use
     -> Int              -- ^ Block size in bytes of the hash function
     -> ByteString       -- ^ Secret key
     -> ByteString       -- ^ Message to MAC
     -> HMAC a
hmac hashF blockSize secret msg = HMAC $ toBytes $ hashF $ B.append opad (toBytes $ hashF $ B.append ipad msg)
    where opad = B.map (xor 0x5c) k'
          ipad = B.map (xor 0x36) k'

          k'  = B.append kt pad
          kt  = if B.length secret > fromIntegral blockSize then toBytes (hashF secret) else secret
          pad = B.replicate (fromIntegral blockSize - B.length kt) 0
