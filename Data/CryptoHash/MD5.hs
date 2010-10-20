-- |
-- Module      : Data.CryptoHash.MD5
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- compatibility module for MD5. use Crypto.Hash.MD5 instead.
--
module Data.CryptoHash.MD5 (
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
import Crypto.Hash.MD5 (Ctx(..))
import qualified Crypto.Hash.MD5 as R
import Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as L (ByteString)

{-# DEPRECATED init "use crypto.hash.MD5" #-}
init :: Ctx
init = R.init

{-# DEPRECATED update "use crypto.hash.MD5" #-}
update :: Ctx -> ByteString -> Ctx
update = R.update

{-# DEPRECATED finalize "use crypto.hash.MD5" #-}
finalize :: Ctx -> ByteString
finalize = R.finalize

{-# DEPRECATED hash "use crypto.hash.MD5" #-}
hash :: ByteString -> ByteString
hash = R.hash

{-# DEPRECATED hashlazy "use crypto.hash.MD5" #-}
hashlazy :: L.ByteString -> ByteString
hashlazy = R.hashlazy
