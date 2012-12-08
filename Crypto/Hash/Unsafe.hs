{-# LANGUAGE CPP #-}

module Crypto.Hash.Unsafe where

import System.IO.Unsafe

unsafeFunc :: IO a -> a
#if __GLASGOW_HASKELL__ > 704
unsafeFunc = unsafeDupablePerformIO
#else
unsafeFunc = unsafePerformIO
#endif

