CryptoHash
==========

hs-cryptohash provides lots of different secure digest algorithms, also
called cryptohashes. It exposes every common hashes, but also some
more exotic hashes, provides an extensive list of hashes available
with a consistant API.

The general performance are comparable to the most optimised hashes
available.

The complete list of supported hashes:

* MD2, MD4, MD5 
* RIPEMD160
* SHA1
* SHA-2 family: 224, 256, 384, 512 and the newer 512t
* SHA-3 (aka Keccak)
* Skein: 256, 512
* Tiger
* Whirlpool

You can easily import any hash with the following:

    import qualified Crypto.Hash.<HASH> as <Hash>

suggestion: it's easier to import qualified since there's
a collision with the init symbol, but for only importing
the hash or hashlazy function there's no such need.

Every hashes, exposes a very similar API.

Incremental API
---------------

it's based on 4 different functions, similar to the lowlevel operations
of a typical hash:

* init: create a new hash context
* update: update non-destructively a new hash context with a strict bytestring
* updates: same as update, except that it takes a list of strict bytestring
* finalize: finalize the context and returns a digest bytestring.

all those operations are completely pure, and instead of changing the
context as usual in others language, it re-allocates a new context each time.

One Pass API
------------

The one pass API use the incremental API under the hood, but expose
common operations to create digests out of a bytestring and lazy bytestring.

* hash: create a digest (init+update+finalize) from a strict bytestring
* hashlazy: create a digest (init+update+finalize) from a lazy bytestring

More Type safety
----------------

A more type safe API is also available from Crypto.Hash. The API provides
all the supported hashes in the same namespace, through unified functions.

It introduces 2 new types, the Context type and the Digest type.
Both those types are parametrized with the HashAlgorithm used.

The API is very similar to each single hash module, except the types are
slightly different.

    import Crypto.Hash

    -- use the incremental API to hash the byte [1,2,3] with SHA1
    -- and print the hexadecimal digest.
    example1 = do
        let ctx = hashInit
            ctx' = hashUpdates ctx [ Data.ByteString.pack [1,2,3] ]
            dgt  = hashFinalize ctx' :: Digest SHA1
        putStrLn $ show dgt

    -- use the one-pass API to hash the byte 1,2,3 with SHA3_512
    -- and print the hexadecimal digest.
    example2 = do
        let dgt  = hash (Data.ByteString.pack [1,2,3]) :: Digest SHA3_512
        putStrLn $ show dgt

Performance
-----------

Cryptohash uses C implementations to provide maximum performance.
see the cbits directory for more information
