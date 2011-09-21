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
* Skein: 256, 512
* Tiger

You can easily import any hash with the following:

    import qualified Crypto.Hash.<HASH> as <Hash>

suggestion: it's easier to import qualified since there's
a collision with the init symbol, but for only importing
the hash or hashlazy function there's no such need.

Every hashes, exposes a very similar API.

Incremental API
---------------

it's based on 3 different functions, similar to the lowlevel operations
of a typical hash:

* init: create a new hash context
* update: update non-destructively a new hash context with a strict bytestring
* finalize: finalize the context and returns a digest bytestring.

all those operations are completely pure, and instead of changing the
context as usual in others language, it create a new context each time.

One Pass API
------------

The one pass API use the incremental API under the hood, but expose
common operations to create digests out of a bytestring and lazy bytestring.

* hash: create a digest (init+update+finalize) from a strict bytestring
* hashlazy: create a digest (init+update+finalize) from a lazy bytestring

Integration with crypto-api
---------------------------

cryptohash is fully integrated with crypto-api and you can use the
related function in crypto-api to use any cryptohash modules.

Performance
-----------

Cryptohash uses C implementations to provides maximum performance.
see the cbits directory for more information
