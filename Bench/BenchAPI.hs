{-# LANGUAGE BangPatterns #-}
import Criterion.Main
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA3 as SHA3
import qualified Crypto.Classes as CAPI

main = do
    let !bs32     = B.replicate 32 0
        !bs256    = B.replicate 256 0
        !bs4096   = B.replicate 4096 0
        !bs1M     = B.replicate (1*1024*1024) 0
    let !lbs64x256 = (map (const (B.replicate 64 0)) [0..3])
        !lbs64x4096 = (map (const (B.replicate 64 0)) [0..63])
    defaultMain
        [ bcompare
            [ bench "sha1.hash 32" $ whnf SHA1.hash bs32
            , bench "sha1.incr 32" $ whnf (SHA1.finalize . SHA1.update SHA1.init) bs32
            , bench "sha1.capi 32" $ whnf (CAPI.hash' :: B.ByteString -> SHA1.SHA1) bs32
            ]
        , bcompare
            [ bench "sha1.hash 256" $ whnf SHA1.hash bs256
            , bench "sha1.incr 256" $ whnf (SHA1.finalize . SHA1.update SHA1.init) bs256
            , bench "sha1.capi 256" $ whnf (CAPI.hash' :: B.ByteString -> SHA1.SHA1) bs256
            ]
        , bcompare
            [ bench "sha1.hash 4096" $ whnf SHA1.hash bs4096
            , bench "sha1.incr 4096" $ whnf (SHA1.finalize . SHA1.update SHA1.init) bs4096
            , bench "sha1.capi 4096" $ whnf (CAPI.hash' :: B.ByteString -> SHA1.SHA1) bs4096
            ]
        ]
