{-# LANGUAGE ForeignFunctionInterface, CPP, MultiParamTypeClasses #-}

-- |
-- Module      : Crypto.Hash.MD2
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing MD2 bindings
--
module Crypto.Hash.MD2
    ( Ctx(..)
    , MD2

    -- * Incremental hashing Functions
    , init     -- :: Ctx
    , update   -- :: Ctx -> ByteString -> Ctx
    , finalize -- :: Ctx -> ByteString

    -- * Single Pass hashing
    , hash     -- :: ByteString -> ByteString
    , hashlazy -- :: ByteString -> ByteString
    ) where

import Prelude hiding (init)
import Foreign.Ptr
import Foreign.ForeignPtr (withForeignPtr)
import Foreign.Storable
import Foreign.Marshal.Alloc
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, toForeignPtr, inlinePerformIO)
import Data.Word

#ifdef HAVE_CRYPTOAPI

import Control.Monad (liftM)
import Data.Serialize (Serialize(..))
import Data.Serialize.Get (getByteString)
import Data.Serialize.Put (putByteString)
import Data.Tagged (Tagged(..))
import qualified Crypto.Classes as C (Hash(..))

instance C.Hash Ctx MD2 where
    outputLength    = Tagged (16 * 8)
    blockLength     = Tagged (16 * 8)
    initialCtx      = init
    updateCtx       = update
    finalize ctx bs = Digest . finalize $ update ctx bs

instance Serialize MD2 where
    get            = liftM Digest (getByteString digestSize)
    put (Digest d) = putByteString d

#endif

data Ctx = Ctx !ByteString
data MD2 = Digest !ByteString
    deriving (Eq,Ord,Show)


{-# INLINE digestSize #-}
digestSize :: Int
digestSize = 16

{-# INLINE sizeCtx #-}
sizeCtx :: Int
sizeCtx = 96

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

foreign import ccall unsafe "md2.h md2_init"
    c_md2_init :: Ptr Ctx -> IO ()

foreign import ccall "md2.h md2_update"
    c_md2_update :: Ptr Ctx -> Ptr Word8 -> Word32 -> IO ()

foreign import ccall unsafe "md2.h md2_finalize"
    c_md2_finalize :: Ptr Ctx -> Ptr Word8 -> IO ()

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
    unsafeUseAsCStringLen d (\(cs, len) -> c_md2_update ptr (castPtr cs) (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr =
    create digestSize (c_md2_finalize ptr)

{-# NOINLINE init #-}
-- | init a context
init :: Ctx
init = inlinePerformIO $ withCtxNew $ c_md2_init

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d = inlinePerformIO $ withCtxCopy ctx $ \ptr -> updateInternalIO ptr d

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = inlinePerformIO $ withCtxThrow ctx finalizeInternalIO

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: ByteString -> ByteString
hash d = inlinePerformIO $ withCtxNewThrow $ \ptr -> do
    c_md2_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: L.ByteString -> ByteString
hashlazy l = inlinePerformIO $ withCtxNewThrow $ \ptr -> do
    c_md2_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
