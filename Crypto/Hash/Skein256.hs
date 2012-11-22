{-# LANGUAGE ForeignFunctionInterface, EmptyDataDecls #-}

-- |
-- Module      : Crypto.Hash.Skein256
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing Skein256 bindings
--
module Crypto.Hash.Skein256
    ( Ctx(..)
    , Skein256

    -- * Incremental hashing Functions
    , init     -- :: Int -> Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: Int -> ByteString -> Digest Skein256
    , hashlazy -- :: Int -> ByteString -> Digest Skein256
    ) where

import Prelude hiding (init)
import Foreign.C.Types
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Storable
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, inlinePerformIO, toForeignPtr)
import Data.Word
import Data.Bits
import Crypto.Hash.Types

data Ctx = Ctx !ByteString
data Skein256

sizeCtx :: Int
sizeCtx = 88

peekHashlen :: Ptr Ctx -> IO Int
peekHashlen ptr = do
    let iptr = castPtr ptr :: Ptr CUInt
    a <- peek iptr
    return ((fromIntegral a + 7) `shiftR` 3)

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

{-# INLINE memcopy64 #-}
memcopy64 :: Ptr Word64 -> Ptr Word64 -> IO ()
memcopy64 dst src = mapM_ peekAndPoke [0..(12-1)]
    where peekAndPoke i = peekElemOff src i >>= pokeElemOff dst i

withCtxCopy :: Ctx -> (Ptr Ctx -> IO ()) -> IO Ctx
withCtxCopy (Ctx ctxB) f = Ctx `fmap` createCtx
    where createCtx = create sizeCtx $ \dstPtr ->
                      withByteStringPtr ctxB $ \srcPtr -> do
                          memcopy64 (castPtr dstPtr) (castPtr srcPtr)
                          f (castPtr dstPtr)

withCtxThrow :: Ctx -> (Ptr Ctx -> IO a) -> IO a
withCtxThrow (Ctx ctxB) f =
    allocaBytes sizeCtx $ \dstPtr ->
    withByteStringPtr ctxB $ \srcPtr -> do
        memcopy64 (castPtr dstPtr) (castPtr srcPtr)
        f (castPtr dstPtr)

withCtxNew :: (Ptr Ctx -> IO ()) -> IO Ctx
withCtxNew f = Ctx `fmap` create sizeCtx (f . castPtr)

withCtxNewThrow :: (Ptr Ctx -> IO a) -> IO a
withCtxNewThrow f = allocaBytes sizeCtx (f . castPtr)

foreign import ccall unsafe "skein256.h skein256_init"
    c_skein256_init :: Ptr Ctx -> Word32 -> IO ()

foreign import ccall "skein256.h skein256_update"
    c_skein256_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "skein256.h skein256_finalize"
    c_skein256_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()


updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_skein256_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO (Digest Skein256)
finalizeInternalIO ptr =
    peekHashlen ptr >>= \digestSize -> (Digest `fmap` create digestSize (c_skein256_finalize ptr))

{-# NOINLINE init #-}
-- | init a context
init :: Int -> Ctx
init hashlen = inlinePerformIO $ withCtxNew $ \ptr -> c_skein256_init ptr (fromIntegral hashlen)

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d = inlinePerformIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> Digest Skein256
finalize ctx = inlinePerformIO $ withCtxThrow ctx finalizeInternalIO

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: Int -> ByteString -> Digest Skein256
hash hashlen d = inlinePerformIO $ withCtxNewThrow $ \ptr -> do
    c_skein256_init ptr (fromIntegral hashlen) >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: Int -> L.ByteString -> Digest Skein256
hashlazy hashlen l = inlinePerformIO $ withCtxNewThrow $ \ptr -> do
    c_skein256_init ptr (fromIntegral hashlen) >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
