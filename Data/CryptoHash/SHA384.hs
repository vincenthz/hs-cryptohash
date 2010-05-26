{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Data.CryptoHash.SHA384
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing SHA384 bindings
--
module Data.CryptoHash.SHA384 (
	Ctx(..),

	-- * Incremental hashing Functions
	init,      -- :: Ctx
	update,    -- :: Ctx -> ByteString -> Ctx
	finalize,  -- :: Ctx -> ByteString

	-- * Single Pass hashing
	hash,      -- :: ByteString -> ByteString
	hashlazy   -- :: ByteString -> ByteString
	) where

import Prelude hiding (init)
import Foreign
import Foreign.C.String
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen, unsafeIndex)
import Data.ByteString.Internal (create)

data Ctx = Ctx ByteString

digestSize :: Int
sizeCtx :: Int

digestSize = 48
sizeCtx = 256

instance Storable Ctx where
	sizeOf _    = sizeCtx
	alignment _ = 16
	poke ptr (Ctx b) = mapM_ (\i -> poke (ptr `plusPtr` i) (unsafeIndex b i)) [0..(sizeCtx-1)]

	peek ptr = do
		b <- create sizeCtx (\bptr -> mapM_ (\i -> do
			f <- peek (ptr `plusPtr` i) :: IO Word8
			poke (bptr `plusPtr` i) f
			) [0..(sizeCtx-1)])
		return $ Ctx $! b

foreign import ccall unsafe "sha512.h sha384_init"
	c_sha384_init :: Ptr Ctx -> IO ()

foreign import ccall unsafe "sha512.h sha384_update"
	c_sha384_update :: Ptr Ctx -> CString -> Word32 -> IO ()

foreign import ccall unsafe "sha512.h sha384_finalize"
	c_sha384_finalize :: Ptr Ctx -> CString -> IO ()

allocInternal :: (Ptr Ctx -> IO a) -> IO a
allocInternal = alloca

allocInternalFrom :: Ctx -> (Ptr Ctx -> IO a) -> IO a
allocInternalFrom ctx f = allocInternal $ \ptr -> (poke ptr ctx >> f ptr)

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
	unsafeUseAsCStringLen d (\(cs, len) -> c_sha384_update ptr cs (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr =
	allocaBytes digestSize (\cs -> c_sha384_finalize ptr cs >> B.packCStringLen (cs, digestSize))

{-# NOINLINE init #-}
-- | init a context
init :: Ctx
init = unsafePerformIO $ allocInternal $ \ptr -> do (c_sha384_init ptr >> peek ptr)

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
	c_sha384_init ptr >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: L.ByteString -> ByteString
hashlazy l = unsafePerformIO $ allocInternal $ \ptr -> do
	c_sha384_init ptr >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
