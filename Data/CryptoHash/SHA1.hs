-- |
-- Module      : Data.CryptoHash.SHA1
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for SHA1. use Crypto.Hash.SHA1 instead.
--
module Data.CryptoHash.SHA1 (
	Ctx(..),

	-- * Incremental hashing Functions
	init,      -- :: Ctx
	update,    -- :: Ctx -> ByteString -> Ctx
	finalize,  -- :: Ctx -> ByteString

	-- * Single Pass hashing
	hash,      -- :: ByteString -> ByteString
	hashlazy   -- :: ByteString -> ByteString
	) where

import Prelude ()
import Crypto.Hash.SHA1 (Ctx(..))
import qualified Crypto.Hash.SHA1 as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.SHA1" #-}
init :: Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.SHA1" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.SHA1" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.SHA1" #-}
hash :: ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.SHA1" #-}
hashlazy :: L.ByteString -> ByteString
hashlazy = R.hashlazy
