{-# LANGUAGE ForeignFunctionInterface, CPP, MultiParamTypeClasses #-}

-- |
-- Module      : Crypto.Hash.MD5
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing MD5 bindings
--
module Crypto.Hash.MD5
	( Ctx(..)
	, MD5

	-- * Incremental hashing Functions
	, init     -- :: Ctx
	, update   -- :: Ctx -> ByteString -> Ctx
	, finalize -- :: Ctx -> ByteString

	-- * Single Pass hashing
	, hash     -- :: ByteString -> ByteString
	, hashlazy -- :: ByteString -> ByteString
	) where

import Prelude hiding (init)
import Foreign
import Foreign.C.String
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCString, unsafeUseAsCStringLen)
import Data.ByteString.Internal (create, memcpy)

#ifdef HAVE_CRYPTOAPI

import Control.Monad (liftM)
import Data.Serialize (Serialize(..))
import Data.Serialize.Get (getByteString)
import Data.Serialize.Put (putByteString)
import Data.Tagged (Tagged(..))
import qualified Crypto.Classes as C (Hash(..))

instance C.Hash Ctx MD5 where
	outputLength    = Tagged (16 * 8)
	blockLength     = Tagged (64 * 8)
	initialCtx      = init
	updateCtx       = update
	finalize ctx bs = Digest . finalize $ update ctx bs

instance Serialize MD5 where
	get            = liftM Digest (getByteString digestSize)
	put (Digest d) = putByteString d

#endif

data Ctx = Ctx !ByteString
data MD5 = Digest !ByteString
	deriving (Eq,Ord,Show)

digestSize, sizeCtx :: Int
digestSize = 16
sizeCtx = 96

instance Storable Ctx where
	sizeOf _    = sizeCtx
	alignment _ = 16
	poke ptr (Ctx b) = unsafeUseAsCString b (\cs -> memcpy (castPtr ptr) (castPtr cs) (fromIntegral sizeCtx))

	peek ptr = create sizeCtx (\bptr -> memcpy bptr (castPtr ptr) (fromIntegral sizeCtx)) >>= return . Ctx

foreign import ccall unsafe "md5.h md5_init"
	c_md5_init :: Ptr Ctx -> IO ()

foreign import ccall "md5.h md5_update"
	c_md5_update :: Ptr Ctx -> CString -> Word32 -> IO ()

foreign import ccall unsafe "md5.h md5_finalize"
	c_md5_finalize :: Ptr Ctx -> CString -> IO ()

allocInternal :: (Ptr Ctx -> IO a) -> IO a
allocInternal = alloca

allocInternalFrom :: Ctx -> (Ptr Ctx -> IO a) -> IO a
allocInternalFrom ctx f = allocInternal $ \ptr -> (poke ptr ctx >> f ptr)

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
	unsafeUseAsCStringLen d (\(cs, len) -> c_md5_update ptr cs (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr =
	allocaBytes digestSize (\cs -> c_md5_finalize ptr cs >> B.packCStringLen (cs, digestSize))

{-# NOINLINE init #-}
-- | init a context
init :: Ctx
init = unsafePerformIO $ allocInternal $ \ptr -> do (c_md5_init ptr >> peek ptr)

{-# NOINLINE update #-}
-- | update a context with a bytestring
update :: Ctx -> ByteString -> Ctx
update ctx d = unsafePerformIO $ allocInternalFrom ctx $ \ptr -> do updateInternalIO ptr d >> peek ptr

{-# NOINLINE finalize #-}
-- | finalize the context into a digest bytestring
finalize :: Ctx -> ByteString
finalize ctx = unsafePerformIO $ allocInternalFrom ctx $ \ptr -> do finalizeInternalIO ptr

{-# NOINLINE hash #-}
-- | hash a strict bytestring into a digest bytestring
hash :: ByteString -> ByteString
hash d = unsafePerformIO $ allocInternal $ \ptr -> do
	c_md5_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafePerformIO $ allocInternal $ \ptr -> do
	c_md5_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
