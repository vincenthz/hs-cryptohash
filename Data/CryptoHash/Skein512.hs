{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Data.CryptoHash.Skein512
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- A module containing Skein512 bindings
--
module Data.CryptoHash.Skein512 (
	Ctx(..),

	-- * Incremental hashing Functions
	init,      -- :: Int -> Ctx
	update,    -- :: Ctx -> ByteString -> Ctx
	finalize,  -- :: Ctx -> ByteString

	-- * Single Pass hashing
	hash,      -- :: Int -> ByteString -> ByteString
	hashlazy   -- :: Int -> ByteString -> ByteString
	) where

import Prelude hiding (init)
import Foreign
import Foreign.C.String
import Foreign.C.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCStringLen, unsafeIndex)
import Data.ByteString.Internal (create)

data Ctx = Ctx !ByteString

sizeCtx :: Int
sizeCtx = 160

instance Storable Ctx where
	sizeOf _    = sizeCtx
	alignment _ = 16
	poke ptr (Ctx b) = do
		mapM_ (\i -> poke (ptr `plusPtr` i) (unsafeIndex b i)) [0..(sizeCtx-1)]

	peek ptr = do
		b <- create sizeCtx (\bptr -> do
			mapM_ (\i -> do
				f <- peek (ptr `plusPtr` i) :: IO Word8
				poke (bptr `plusPtr` i) f
				) [0..(sizeCtx-1)]
			)
		return $ Ctx b

poke_hashlen :: Ptr Ctx -> IO Int
poke_hashlen ptr = do
	a <- peek (ptr `plusPtr` 3)
	b <- peek (ptr `plusPtr` 2)
	c <- peek (ptr `plusPtr` 1)
	d <- peek (ptr `plusPtr` 0)
	return (sl a 24 .|. sl b 16 .|. sl c 8 .|. sl d 0)
	where
		sl :: Word8 -> Int -> Int
		sl a r = (fromIntegral a) `shiftL` r

foreign import ccall unsafe "skein512.h skein512_init"
	c_skein512_init :: Ptr Ctx -> CUInt -> IO ()

foreign import ccall "skein512.h skein512_update"
	c_skein512_update :: Ptr Ctx -> CString -> Word32 -> IO ()

foreign import ccall unsafe "skein512.h skein512_finalize"
	c_skein512_finalize :: Ptr Ctx -> CString -> IO ()

allocInternal :: (Ptr Ctx -> IO a) -> IO a
allocInternal = alloca

allocInternalFrom :: Ctx -> (Ptr Ctx -> IO a) -> IO a
allocInternalFrom ctx f = allocInternal $ \ptr -> (poke ptr ctx >> f ptr)

updateInternalIO :: Ptr Ctx -> ByteString -> IO ()
updateInternalIO ptr d =
	unsafeUseAsCStringLen d (\(cs, len) -> c_skein512_update ptr cs (fromIntegral len))

finalizeInternalIO :: Ptr Ctx -> IO ByteString
finalizeInternalIO ptr = do
	digestSize <- fmap (\x -> (x + 7) `shiftR` 3) $ poke_hashlen ptr
	allocaBytes digestSize (\cs -> c_skein512_finalize ptr cs >> B.packCStringLen (cs, digestSize))

{-# NOINLINE init #-}
-- | init a context
init :: Int -> Ctx
init hashlen = unsafePerformIO $ allocInternal $ \ptr -> do (c_skein512_init ptr (fromIntegral hashlen) >> peek ptr)

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
hash :: Int -> ByteString -> ByteString
hash hashlen d = unsafePerformIO $ allocInternal $ \ptr -> do
	c_skein512_init ptr (fromIntegral hashlen) >> updateInternalIO ptr d >> finalizeInternalIO ptr

{-# NOINLINE hashlazy #-}
-- | hash a lazy bytestring into a digest bytestring
hashlazy :: Int -> L.ByteString -> ByteString
hashlazy hashlen l = unsafePerformIO $ allocInternal $ \ptr -> do
	c_skein512_init ptr (fromIntegral hashlen) >> mapM_ (updateInternalIO ptr) (L.toChunks l) >> finalizeInternalIO ptr
