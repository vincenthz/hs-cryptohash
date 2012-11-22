{-# LANGUAGE EmptyDataDecls #-}
-- |
-- Module      : Crypto.Hash.SHA512t
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA512/t
--
module Crypto.Hash.SHA512t
    ( Ctx(..)
    , SHA512t

    -- * Incremental hashing Functions
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Data.List (foldl')
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Hash.SHA512 as SHA512
import Crypto.Hash.Types

data Ctx = Ctx !Int !SHA512.Ctx
data SHA512t

-- | init a context
init :: Int -> Ctx
init t = Ctx t (SHA512.init_t t)

-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update (Ctx t ctx) d = Ctx t (SHA512.update ctx d)

-- | finalize the context into a digest bytestring
finalize :: Ctx -> Digest SHA512t
finalize (Ctx sz ctx) = Digest $ B.take (sz `div` 8) digest
    where (Digest digest) = SHA512.finalize ctx

-- | hash a strict bytestring into a digest bytestring
hash :: Int -> ByteString -> Digest SHA512t
hash t = finalize . update (init t)

-- | hash a lazy bytestring into a digest bytestring
hashlazy :: Int -> L.ByteString -> Digest SHA512t
hashlazy t = finalize . foldl' update (init t) . L.toChunks
