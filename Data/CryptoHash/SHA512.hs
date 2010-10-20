-- |
-- Module      : Data.CryptoHash.SHA512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for SHA512. use Crypto.Hash.SHA512 instead.
--
module Data.CryptoHash.SHA512 (
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
import Crypto.Hash.SHA512 (Ctx(..))
import qualified Crypto.Hash.SHA512 as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.SHA512" #-}
init :: Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.SHA512" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.SHA512" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.SHA512" #-}
hash :: ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.SHA512" #-}
hashlazy :: L.ByteString -> ByteString
hashlazy = R.hashlazy
