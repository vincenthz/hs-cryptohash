{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.Hash.SHA3
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA3 bindings
--
module Crypto.Hash.SHA3
    ( Ctx(..)

    -- * Incremental hashing Functions
    , init     -- :: Int -> Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: Int -> ByteString -> ByteString
    , hashlazy -- :: Int -> ByteString -> ByteString
    ) where

import Prelude hiding (init)
import System.IO.Unsafe (unsafePerformIO)
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Storable
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, toForeignPtr)
import Data.Word

data Ctx = Ctx !ByteString

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 360

{- return the number of bytes of output for the digest -}
peekHashlen :: Ptr Ctx -> IO Int
peekHashlen ptr = peek iptr >>= \v -> return $! fromIntegral v
    where iptr :: Ptr Word32
          iptr = castPtr ptr

{-# INLINE withByteStringPtr #-}
withByteStringPtr :: ByteString -> (Ptr Word8 -> IO a) -> IO a
withByteStringPtr b f =
    withForeignPtr fptr $ \ptr -> f (ptr `plusPtr` off)
    where (fptr, off, _) = toForeignPtr b

{-# INLINE memcopy64 #-}
memcopy64 :: Ptr Word64 -> Ptr Word64 -> IO ()
memcopy64 dst src = mapM_ peekAndPoke [0..44]
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

foreign import ccall unsafe "sha3.h sha3_init"
    c_sha3_init :: Ptr Ctx -> Word32 -> IO ()

foreign import ccall "sha3.h sha3_update"
    c_sha3_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "sha3.h sha3_finalize"
    c_sha3_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_sha3_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr =
    peekHashlen ptr >>= \digestSize -> create digestSize (c_sha3_finalize ptr)

{-# NOINLINE init #-}
-- | init a context
init :: Int -> Ctx
init hashlen = unsafePerformIO $ withCtxNew (\ctx -> c_sha3_init ctx (fromIntegral hashlen))

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d = unsafePerformIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = unsafePerformIO $ withCtxThrow ctx finalizeInternalIO

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: Int -> ByteString -> ByteString
hash hashlen d = unsafePerformIO $ withCtxNewThrow $ \ptr -> do
    c_sha3_init ptr (fromIntegral hashlen) >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: Int -> L.ByteString -> ByteString
hashlazy hashlen l = unsafePerformIO $ withCtxNewThrow $ \ptr -> do
    c_sha3_init ptr (fromIntegral hashlen) >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
