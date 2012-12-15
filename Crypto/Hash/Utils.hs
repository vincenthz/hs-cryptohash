{-# LANGUAGE MagicHash, BangPatterns #-}
-- |
-- Module      : Crypto.Hash.Utils
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- Crypto hash utility for hexadecimal
--
module Crypto.Hash.Utils
    ( toHex
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B
import GHC.Prim
import GHC.Types
import GHC.Word
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Ptr (plusPtr)
import Foreign.Storable (poke, peek)

toHex :: ByteString -> ByteString
toHex (B.PS fp off len) = B.unsafeCreate (len*2) $ \d ->
        withForeignPtr fp $ \s -> start d (s `plusPtr` off)
    where start db sb = loop db sb
                where end            = sb `plusPtr` len
                      loop d s
                         | s == end  = return ()
                         | otherwise = do b <- fromIntegral `fmap` (peek s :: IO Word8)
                                          poke d               (r tableHi b)
                                          poke (d `plusPtr` 1) (r tableLo b)
                                          loop (d `plusPtr` 2) (s `plusPtr` 1)

          r :: Addr# -> Int -> Word8
          r table (I# index) = W8# (indexWord8OffAddr# table index)

          !tableLo =
                "0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef\
                \0123456789abcdef0123456789abcdef"#
          !tableHi =
                "00000000000000001111111111111111\
                \22222222222222223333333333333333\
                \44444444444444445555555555555555\
                \66666666666666667777777777777777\
                \88888888888888889999999999999999\
                \aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb\
                \ccccccccccccccccdddddddddddddddd\
                \eeeeeeeeeeeeeeeeffffffffffffffff"#
