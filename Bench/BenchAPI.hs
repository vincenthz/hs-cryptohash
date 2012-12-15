{-# LANGUAGE BangPatterns #-}
import Criterion.Main
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA3 as SHA3
import Crypto.Hash
import qualified Crypto.Classes as CAPI

sha1F = ( "sha1"
        , SHA1.hash
        , SHA1.finalize . SHA1.update SHA1.init
        , digestToByteString . (hash :: B.ByteString -> Digest SHA1)
        , CAPI.hash' :: B.ByteString -> SHA1.SHA1
        )

sha512F = ( "sha1"
        , SHA512.hash
        , SHA512.finalize . SHA512.update SHA512.init
        , digestToByteString . (hash :: B.ByteString -> Digest SHA512)
        , CAPI.hash' :: B.ByteString -> SHA512.SHA512
        )

main = do
    let !bs32     = B.replicate 32 0
        !bs256    = B.replicate 256 0
        !bs4096   = B.replicate 4096 0
        !bs1M     = B.replicate (1*1024*1024) 0
    let !lbs64x256 = (map (const (B.replicate 64 0)) [0..3])
        !lbs64x4096 = (map (const (B.replicate 64 0)) [0..63])

    let (fname, fHash, fIncr, fAPI, fCAPI) = sha512F
    let benchName ty z = fname ++ "." ++ ty ++ " " ++ show z
    defaultMain
        [ bgroup "digest hex"
            [ bench "hex" $ whnf digestToHexByteString (hashsha1 B.empty)
            ]
        , bcompare
            [ bench (benchName "hash" 0) $ whnf fHash B.empty
            , bench (benchName "incr" 0) $ whnf fIncr B.empty
            , bench (benchName "api" 0)  $ whnf fAPI B.empty
            , bench (benchName "capi" 0) $ whnf fCAPI B.empty
            ]
        , bcompare
            [ bench (benchName "hash" 32) $ whnf SHA1.hash bs32
            , bench (benchName "incr" 32) $ whnf fIncr bs32
            , bench (benchName "api" 32)  $ whnf fAPI bs32
            , bench (benchName "capi" 32) $ whnf fCAPI bs32
            ]
        , bcompare
            [ bench (benchName "hash" 256) $ whnf SHA1.hash bs256
            , bench (benchName "incr" 256) $ whnf fIncr bs256
            , bench (benchName "api" 256)  $ whnf fAPI bs256
            , bench (benchName "capi" 256) $ whnf fCAPI bs256
            ]
        , bcompare
            [ bench (benchName "hash" 4096) $ whnf SHA1.hash bs4096
            , bench (benchName "incr" 4096) $ whnf fIncr bs4096
            , bench (benchName "api" 4096)  $ whnf fAPI bs4096
            , bench (benchName "capi" 4096) $ whnf fCAPI bs4096
            ]
        ]
    where hashsha1 = hash :: B.ByteString -> Digest SHA1
