-- |
-- Module      : Data.CryptoHash.Tiger
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for Tiger. use Crypto.Hash.Tiger instead.
--
module Data.CryptoHash.Tiger (
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
import Crypto.Hash.Tiger (Ctx(..))
import qualified Crypto.Hash.Tiger as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.Tiger" #-}
init :: Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.Tiger" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.Tiger" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.Tiger" #-}
hash :: ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.Tiger" #-}
hashlazy :: L.ByteString -> ByteString
hashlazy = R.hashlazy
