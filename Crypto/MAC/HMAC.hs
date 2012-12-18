-- |
-- Module      : Crypto.MAC.HMAC
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- provide the HMAC (Hash based Message Authentification Code) base algorithm.
-- http://en.wikipedia.org/wiki/HMAC
--
module Crypto.MAC.HMAC
    ( hmac
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits (xor)
import Crypto.Hash

-- | compute a MAC using the supplied hashing function
hmac :: (ByteString -> Digest a) -> Int -> ByteString -> ByteString -> ByteString
hmac hashF blockSize secret msg = digestToByteString $ hashF $ B.append opad (digestToByteString $ hashF $ B.append ipad msg)
    where opad = B.map (xor 0x5c) k'
          ipad = B.map (xor 0x36) k'

          k'  = B.append kt pad
          kt  = if B.length secret > fromIntegral blockSize then digestToByteString (hashF secret) else secret
          pad = B.replicate (fromIntegral blockSize - B.length kt) 0
