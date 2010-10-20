-- |
-- Module      : Data.CryptoHash.MD4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for MD4. use Crypto.Hash.MD4 instead.
--
module Data.CryptoHash.MD4 (
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
import Crypto.Hash.MD4 (Ctx(..))
import qualified Crypto.Hash.MD4 as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.MD4" #-}
init :: Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.MD4" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.MD4" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.MD4" #-}
hash :: ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.MD4" #-}
hashlazy :: L.ByteString -> ByteString
hashlazy = R.hashlazy
