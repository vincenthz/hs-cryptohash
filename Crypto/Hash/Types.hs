module Crypto.Hash.Types
    ( HashAlgorithm(..)
    , Context(..)
    , Digest(..)
    )
    where

import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Crypto.Hash.Utils (toHex)

-- | Class representing hashing algorithms.
--
-- The hash algorithm is built over 3 primitives:
--
--   init     : create a new context
--   updates  : update the context with some strict bytestrings
--   finalize : finalize the context into a digest
--
class HashAlgorithm a where
    -- | Initialize a new context for this hash algorithm
    hashInit     :: Context a

    -- | Update the context with a list of strict bytestring,
    -- and return a new context with the updates.
    hashUpdates  :: Context a -> [ByteString] -> Context a

    -- | Finalize a context and return a digest.
    hashFinalize :: Context a -> Digest a

-- | Represent a context for a given hash algorithm.
newtype Context a = Context { contextToByteString :: ByteString }

-- | Represent a digest for a given hash algorithm.
newtype Digest a = Digest { digestToByteString :: ByteString }
    deriving (Eq,Ord)

instance Show (Digest a) where
    show (Digest bs) = BC.unpack $ toHex bs
