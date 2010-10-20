-- |
-- Module      : Data.CryptoHash.Skein256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for Skein256. use Crypto.Hash.Skein256 instead.
--
module Data.CryptoHash.Skein256 (
	Ctx(..),

	-- * Incremental hashing Functions
	init,      -- :: Int -> Ctx
	update,    -- :: Ctx -> ByteString -> Ctx
	finalize,  -- :: Ctx -> ByteString

	-- * Single Pass hashing
	hash,      -- :: Int -> ByteString -> ByteString
	hashlazy   -- :: Int -> ByteString -> ByteString
	) where

import Prelude (Int)
import Crypto.Hash.Skein256 (Ctx(..))
import qualified Crypto.Hash.Skein256 as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.Skein256" #-}
init :: Int -> Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.Skein256" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.Skein256" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.Skein256" #-}
hash :: Int -> ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.Skein256" #-}
hashlazy :: Int -> L.ByteString -> ByteString
hashlazy = R.hashlazy
