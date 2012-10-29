import Criterion.Main
import qualified Data.ByteString as B
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD4 as MD4
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.SHA512t as SHA512t
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.Tiger as Tiger
import qualified Crypto.Hash.Skein256 as Skein256
import qualified Crypto.Hash.Skein512 as Skein512
import qualified Crypto.Hash.Whirlpool as Whirlpool

allHashs =
	[ ("MD2",MD2.hash)
	, ("MD4",MD4.hash)
	, ("MD5",MD5.hash)
	, ("SHA1",SHA1.hash)
	, ("SHA224",SHA224.hash)
	, ("SHA256",SHA256.hash)
	, ("SHA384",SHA384.hash)
	, ("SHA512",SHA512.hash)
	, ("SHA512t-512",(SHA512t.hash 512))
	, ("RIPEMD160",RIPEMD160.hash)
	, ("Tiger",Tiger.hash)
	, ("Skein256-256",Skein256.hash 256)
	, ("Skein512-512",Skein512.hash 512)
    , ("Whirlpool",Whirlpool.hash)
	]

benchHash :: Int -> (B.ByteString -> B.ByteString) -> Pure
benchHash sz f = whnf f (B.replicate sz 0)

withHashes f = map f allHashs

main = defaultMain
	[ bgroup "hash-256b" (withHashes (\(name, f) -> bench name $ benchHash 256 f))
	, bgroup "hash-4Kb" (withHashes (\(name, f) -> bench name $ benchHash 4096 f))
	, bgroup "hash-1Mb" (withHashes (\(name, f) -> bench name $ benchHash (1*1024*1024) f))
	]
