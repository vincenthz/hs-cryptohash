-- |
-- Module      : Data.CryptoHash.RIPEMD160
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for RIPEMD160. use Crypto.Hash.RIPEMD160 instead.
--
module Data.CryptoHash.RIPEMD160 (
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
import Crypto.Hash.RIPEMD160 (Ctx(..))
import qualified Crypto.Hash.RIPEMD160 as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.RIPEMD160" #-}
init :: Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.RIPEMD160" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.RIPEMD160" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.RIPEMD160" #-}
hash :: ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.RIPEMD160" #-}
hashlazy :: L.ByteString -> ByteString
hashlazy = R.hashlazy
