{-# LANGUAGE CPP #-}

module Crypto.Hash.Internal where

import System.IO.Unsafe

unsafeDoIO :: IO a -> a
#if __GLASGOW_HASKELL__ > 704
unsafeDoIO = unsafeDupablePerformIO
#else
unsafeDoIO = unsafePerformIO
#endif

