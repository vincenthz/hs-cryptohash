import Test.HUnit
import Data.Char
import Data.Bits
import Data.Word
import qualified Data.ByteString as B
import qualified Crypto.Hash.MD2 as MD2
import qualified Crypto.Hash.MD4 as MD4
import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA224 as SHA224
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA384 as SHA384
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Hash.RIPEMD160 as RIPEMD160
import qualified Crypto.Hash.Tiger as Tiger
import qualified Crypto.Hash.Skein256 as Skein256
import qualified Crypto.Hash.Skein512 as Skein512

v0 = ""
v1 = "The quick brown fox jumps over the lazy dog"
v2 = "The quick brown fox jumps over the lazy cog"
vectors = [ v0, v1, v2 ]

data HashFct = HashFct
	{ fctHash   :: (B.ByteString -> B.ByteString)
	, fctInc    :: ([B.ByteString] -> B.ByteString) }

hashinc i u f = f . foldl u i

md2Hash    = HashFct { fctHash = MD2.hash, fctInc = hashinc MD2.init MD2.update MD2.finalize }
md4Hash    = HashFct { fctHash = MD4.hash, fctInc = hashinc MD4.init MD4.update MD4.finalize }
md5Hash    = HashFct { fctHash = MD5.hash, fctInc = hashinc MD5.init MD5.update MD5.finalize }
sha1Hash   = HashFct { fctHash = SHA1.hash, fctInc = hashinc SHA1.init SHA1.update SHA1.finalize }
sha224Hash = HashFct { fctHash = SHA224.hash, fctInc = hashinc SHA224.init SHA224.update SHA224.finalize }
sha256Hash = HashFct { fctHash = SHA256.hash, fctInc = hashinc SHA256.init SHA256.update SHA256.finalize }
sha384Hash = HashFct { fctHash = SHA384.hash, fctInc = hashinc SHA384.init SHA384.update SHA384.finalize }
sha512Hash = HashFct { fctHash = SHA512.hash, fctInc = hashinc SHA512.init SHA512.update SHA512.finalize }
ripemd160Hash = HashFct { fctHash = RIPEMD160.hash, fctInc = hashinc RIPEMD160.init RIPEMD160.update RIPEMD160.finalize }
tigerHash = HashFct { fctHash = Tiger.hash, fctInc = hashinc Tiger.init Tiger.update Tiger.finalize }

skein256Hash x = HashFct { fctHash = Skein256.hash x, fctInc = hashinc (Skein256.init x) Skein256.update Skein256.finalize }
skein512Hash x = HashFct { fctHash = Skein512.hash x, fctInc = hashinc (Skein512.init x) Skein512.update Skein512.finalize }

results :: [ (String, HashFct, [String]) ]
results = [
	("MD2", md2Hash, [
		"8350e5a3e24c153df2275c9f80692773",
		"03d85a0d629d2c442e987525319fc471",
		"6b890c9292668cdbbfda00a4ebf31f05" ]),
	("MD4", md4Hash, [
		"31d6cfe0d16ae931b73c59d7e0c089c0",
		"1bee69a46ba811185c194762abaeae90",
		"b86e130ce7028da59e672d56ad0113df" ]),
	("MD5", md5Hash, [
		"d41d8cd98f00b204e9800998ecf8427e",
		"9e107d9d372bb6826bd81d3542a419d6",
		"1055d3e698d289f2af8663725127bd4b" ]),
	("SHA1", sha1Hash, [
		"da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
		"de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3" ]),
	("SHA224", sha224Hash, [
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
		"730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
		"fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b" ]),
	("SHA256", sha256Hash, [
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		"e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be" ]),
	("SHA384", sha384Hash, [
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
		"ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
		"098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b" ]),
	("SHA512", sha512Hash, [
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		"07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
		"3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045" ]),
	("RIPEMD160", ripemd160Hash, [
		"9c1185a5c5e9fc54612808977ee8f548b2258d31",
		"37f332f68db77bd9d7edd4969571ad671cf9dd3b",
		"132072df690933835eb8b6ad0b77e7b6f14acad7" ]),
	("Tiger", tigerHash, [
		"3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
		"6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075",
		"a8f04b0f7201a0d728101c9d26525b31764a3493fcd8458f" ])
	, ("Skein256-160", skein256Hash 160, [
		"2ab89f14cfb3a5cb4655379386c42df7a45ccaf7",
		"c86ef8411dc1deb008a3c175091691b74643631e",
		"2775e79484bc087b58eb78d977c143a3029471be" ])
	, ("Skein256-256", skein256Hash 256, [
		"0b04103b828cddaebcf592ac845ecafd5887f61230a755406d38d85376e1ae08",
		"a7e63c4dc73d0cb77184e319ebb6f69b73bfc8b945c1b371fafd01223a2ade1c",
		"2174ca46353601a53826b430b52e76fca51bb0419f7a20ac7ffd53c4c448fa51" ])
	, ("Skein512-160", skein512Hash 160, [
		"b034bcc065b01b0c486159b3dba3e03aa52fdd70",
		"9709e7d913bc3eee240e1f302840a0da9d9acc48",
		"fb2cc0959e884d66927346552df8b51d2d98690c" ])
	, ("Skein512-384", skein512Hash 384, [
		"2c3fe10673f4d6904f27585fc3df455a678bc12d7d39d6be4b37f47b80a43889181103bc727a7db4b4e2d2dec1ded86a",
		"19d373842a6dd304454d6673cb3a8b7871f139477ac28900de739a31789f6e2846d3b641b2e8386f65061efe602d7cac",
		"bbc4e1089364dd69b0847a06bff6ce19889fed18bf57c901402c74e22ba763bf0dacb9b1d24efc78d969170fd434dad7" ])
	, ("Skein512-512", skein512Hash 512, [
		"5af68a4912e0a6187a004947a9d2a37d7a1f0873f0bdd9dc64838ece60da5535c2a55d039bd58e178948996b7a8336486ed969c894be658e47d595a5a9b86a8b",
		"e38e8ec4814aa2ca485c8ace47c929691ec6acabf2d2795006306267210728d5576d6b7d361bbf99fb1e843d9027b340f828ad074315a5d4b71361de34c511c0",
		"cd90f50e10e7fe59e263c3796b92795a78fcf561f0fea07b04faeb4e602edb4d6d9f927cc0b5f2b0671e7c7e5fc42ca8875222bcfd42936c542d8f2312fd3615" ])
	, ("Skein512-896", skein512Hash 896, [
		"bcc274c53cfa75284f8dcf71e28d19bf52f0e218c241cc1c23e2da043bf61c383899c67fdcbb7511de1831a9113720125127876df2bd0cd57d99ef303baf209c00998bc7d3749f6845d9eaf32ac629de84ac3b494efa29a68cb93d65fd25a2dcef515484b78381eede4af762a1d2f188",
		"7ad8b71b5bdcaff6f785c9b80b2b1f5fe56030f3ead98965d1ebd20ae75388c2e94097b32a01b7d11a32cef60ea9268170db51726cddf9ee62c3f33e3f84f8ec470053affb564952da6a9cb5e8a4baba8e72b9612ea95863c99b7e59a461288459990ef063fe0b066f8f24fb3794e708",
		"14b22fe85d5b22f8aa921f32bab0e2cca9d88971dd6f7624506c6662faec9c7429be5bc54be37734c52f10cd866612d0e364023e1db888579b6d9462530807ade129d308adb09eb3308ad8c8731aedb1559f6cefd7d4d9761627f727a79a149788fb267439004d5f7a8dad69a6046d8b" ])
	]

hexalise s =
        concatMap (\c -> [ hex $ c `div` 16, hex $ c `mod` 16 ]) s
        where hex i
                | i >= 0 && i <= 9   = fromIntegral (ord '0') + i
                | i >= 10 && i <= 15 = fromIntegral (ord 'a') + i - 10
                | otherwise          = 0

hexaliseB :: B.ByteString -> B.ByteString
hexaliseB = B.pack . hexalise . B.unpack

splitB l b =
	if B.length b > l
		then
			let (b1, b2) = B.splitAt l b in
			b1 : splitB l b2
		else	
			[ b ]

showHash :: B.ByteString -> String
showHash = map (toEnum.fromEnum) . hexalise . B.unpack

runhash hash v = showHash $ (fctHash hash) $ v
runhashinc hash v = showHash $ (fctInc hash) $ v

makeTestAlg (name, hash, results) = concatMap maketest $ zip3 [0..] vectors results
	where
		testname i = name ++ " " ++ show i
		runtest v = runhash hash $ B.pack $ map (toEnum.fromEnum) v

		runtestinc i v = runhashinc hash $ splitB i $ B.pack $ map (toEnum.fromEnum) v

		maketest (i, v, r) =
			[ testname i ~: testname i ~: r ~=? (runtest v),
			  testname i ~: testname i ~: r ~=? (runtestinc 1 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 2 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 3 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 4 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 5 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 9 v),
			  testname i ~: testname i ~: r ~=? (runtestinc 16 v) ]

mapTests :: [Test]
mapTests = concatMap makeTestAlg results

tests = TestList mapTests

main = runTestTT tests
