-- |
-- Module      : Crypto.MAC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash generic MAC (Message Authentification Code) module
--
module Crypto.MAC
    (
    -- * MAC algorithms
      HMAC(..)
    , hmac
    , hmacAlg
    -- ** Incremental MAC algorithms
    , HMACContext
    , hmacInit
    , hmacInitAlg
    , hmacUpdate
    , hmacFinalize
    ) where

import Crypto.Hash
import Data.ByteString (ByteString)
import Data.Byteable
import Data.Bits (xor)
import qualified Data.ByteString as B

-- -------------------------------------------------------------------------- --
-- Incremental HMAC

data HMACContext hashalg = HMACContext ByteString (Context hashalg)

hmacInit :: HashAlgorithm a
         => ByteString -- ^ Secret key
         -> HMACContext a
hmacInit secret = HMACContext secret hctx
    where ctxInit = hashInit
          hctx = hashUpdates ctxInit [ipad]
          ipad = B.map (xor 0x36) k'

          k'  = B.append kt pad
          kt  = if B.length secret > fromIntegral blockSize then toBytes (hashF secret) else secret
          pad = B.replicate (fromIntegral blockSize - B.length kt) 0
          hashF = hashFinalize . hashUpdate ctxInit
          blockSize = hashBlockSize ctxInit

hmacInitAlg :: HashAlgorithm a
            => a           -- ^ the hash algorithm the actual value is unused.
            -> ByteString  -- ^ Secret key
            -> HMACContext a
hmacInitAlg _ secret = hmacInit secret

hmacUpdate :: HashAlgorithm a
           => HMACContext a
           -> ByteString -- ^ Message to Mac
           -> HMACContext a
hmacUpdate (HMACContext secret hctx) msg = HMACContext secret (hashUpdate hctx msg)

hmacFinalize :: HashAlgorithm a
             => HMACContext a
             -> HMAC a
hmacFinalize (HMACContext secret hctx) = HMAC $ hashF $ B.append opad $ (toBytes $ hashFinalize hctx)
    where ctxInit = hashInit
          opad = B.map (xor 0x5c) k'

          k'  = B.append kt pad
          kt  = if B.length secret > fromIntegral blockSize then toBytes (hashF secret) else secret
          pad = B.replicate (fromIntegral blockSize - B.length kt) 0
          hashF = hashFinalize . hashUpdate ctxInit
          blockSize = hashBlockSize ctxInit
