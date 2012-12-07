{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Hash.Types
    ( HashAlgorithm(..)
    , Context(..)
    , Digest(..)
    )
    where

import Data.ByteString (ByteString)

class HashAlgorithm a where
    hashInit     :: Context a
    hashUpdates  :: Context a -> [ByteString] -> Context a
    hashFinalize :: Context a -> Digest a

newtype Context a = Context { contextToByteString :: ByteString }

newtype Digest a = Digest { digestToByteString :: ByteString }
    deriving (Eq,Ord)
