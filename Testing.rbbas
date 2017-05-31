#tag Module
Protected Module Testing
	#tag Method, Flags = &h21
		Private Sub Assert(b As Boolean)
		  If Not b Then Raise New RuntimeException
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RunTests() As Boolean
		  Try
		    TestPKIEncrypt()
		  Catch
		    Failures.Append(1)
		  End Try
		  
		  Try
		    TestPKISign()
		  Catch
		    Failures.Append(2)
		  End Try
		  
		  Try
		    TestUtils()
		  Catch
		    Failures.Append(3)
		  End Try
		  
		  Try
		    TestPassword()
		  Catch
		    Failures.Append(4)
		  End Try
		  
		  Try
		    TestSecureMemory()
		  Catch
		    Failures.Append(5)
		  End Try
		  
		  Try
		    TestHash()
		  Catch
		    Failures.Append(6)
		  End Try
		  
		  Try
		    TestPKIForeignKey()
		  Catch
		    Failures.Append(7)
		  End Try
		  
		  Try
		    TestPKIExchange()
		  Catch
		    Failures.Append(8)
		  End Try
		  
		  Try
		    TestPKISeal()
		  Catch
		    Failures.Append(9)
		  End Try
		  
		  Try
		    TestSKIMAC()
		  Catch
		    Failures.Append(10)
		  End Try
		  
		  Try
		    TestKeyStream_ChaCha20()
		  Catch
		    Failures.Append(11)
		  End Try
		  
		  Try
		    TestKeyStream_Salsa20()
		  Catch
		    Failures.Append(12)
		  End Try
		  
		  Try
		    TestKeyStream_XSalsa20()
		  Catch
		    Failures.Append(13)
		  End Try
		  
		  Return UBound(Failures) = -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestHash()
		  Const key = "27F2B73F7A94144A7F459792892D2CFFB78FB442FE64D451EDB63B08DA940C27"
		  Const hash = "9BE9B8EB8DD91BCC39C1A0AD306FBFDBBCC7872AEDCBDB60BB9961B1AD341A845E65ECB18859F488FB262D99DA5CB3CE5ADD0D968A1260BE6F804B25EF2BB2B9"
		  // The quick brown fox jumps over the lazy dog.
		  Const test_message = "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e"
		  
		  Assert(EncodeHex(libsodium.GenericHash("Hello, world!", DecodeHex(key))) = hash)
		  
		  Assert(libsodium.EncodeHex(libsodium.SHA256("Hello, world!")) = "315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC94C75894EDD3")
		  Assert(libsodium.EncodeHex(libsodium.SHA512("Hello, world!")) = "C1527CD893C124773D811911970C8FE6E857D6DF5DC9226BD8A160614C0CD963A4DDEA2B94BB7D36021EF9D865D5CEA294A82DD49A0BB269F51F6E7A57F79421")
		  
		  
		  // Taken from the NSRL test vectors = http://www.nsrl.nist.gov/testdata/
		  Const sha256_digest = "EF537F25C895BFA782526529A9B63D97AA631564D5D789C2B765448C8635FB6C"
		  Const sha256_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		  
		  Dim h, m As MemoryBlock
		  h = libsodium.SHA256(DecodeHex(test_message))
		  m = DecodeHex(sha256_digest)
		  Assert(h = m)
		  
		  h = libsodium.SHA256("")
		  m = DecodeHex(sha256_empty)
		  Assert(h = m)
		  
		  Const sha512_digest = "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"
		  Const sha512_empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
		  
		  h = libsodium.SHA512(DecodeHex(test_message))
		  m = DecodeHex(sha512_digest)
		  Assert(h = m)
		  
		  // the empty string
		  h = libsodium.SHA512("")
		  m = DecodeHex(sha512_empty)
		  Assert(h = m)
		  
		  
		  // The quick brown fox jumps over the lazy dog [no ending period]
		  Const test_message1 = "54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F67"
		  
		  Const blake2b_digest = "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918"
		  Const blake2b_empty = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
		  
		  h = libsodium.GenericHash(DecodeHex(test_message1))
		  m = DecodeHex(blake2b_digest)
		  Assert(h = m)
		  
		  // the empty string
		  h = libsodium.GenericHash("")
		  m = DecodeHex(blake2b_empty)
		  Assert(h = m)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestKeyStream_ChaCha20()
		  ' ChaCha20 test vectors taken from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
		  
		  Dim prefix As String = DecodeHex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
		  Dim key As libsodium.PKI.ForeignKey = DecodeHex("0000000000000000000000000000000000000000000000000000000000000000")
		  Dim nonce As String = DecodeHex("0000000000000000")
		  Dim ks As New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.ChaCha20)
		  Dim output As String = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		  
		  prefix = DecodeHex("4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963")
		  key = DecodeHex("0000000000000000000000000000000000000000000000000000000000000001")
		  nonce = DecodeHex("0000000000000000")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.ChaCha20)
		  output = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		  
		  prefix = DecodeHex("de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3")
		  key = DecodeHex("0000000000000000000000000000000000000000000000000000000000000000")
		  nonce = DecodeHex("0000000000000001")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.ChaCha20)
		  output = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		  
		  prefix = DecodeHex("ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b")
		  key = DecodeHex("0000000000000000000000000000000000000000000000000000000000000000")
		  nonce = DecodeHex("0100000000000000")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.ChaCha20)
		  output = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestKeyStream_Salsa20()
		  ' salsa20 test vectors taken from https://github.com/alexwebr/salsa20/blob/master/test_vectors.256
		  
		  Dim prefix As String = DecodeHex("5E5E71F90199340304ABB22A37B6625BF883FB89CE3B21F54A10B81066EF87DA30B77699AA7379DA595C77DD59542DA208E5954F89E40EB7AA80A84A6176663F")
		  Dim key As libsodium.PKI.ForeignKey = DecodeHex("0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C")
		  Dim nonce As String = DecodeHex("288FF65DC42B92F9")
		  Dim ks As New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.Salsa20)
		  Dim output As String = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		  
		  prefix = DecodeHex("3FE85D5BB1960A82480B5E6F4E965A4460D7A54501664F7D60B54B06100A37FFDCF6BDE5CE3F4886BA77DD5B44E95644E40A8AC65801155DB90F02522B644023")
		  key = DecodeHex("0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417")
		  nonce = DecodeHex("1F86ED54BB2289F0")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.Salsa20)
		  output = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		  
		  prefix = DecodeHex("3944F6DC9F85B128083879FDF190F7DEE4053A07BC09896D51D0690BD4DA4AC1062F1E47D3D0716F80A9B4D85E6D6085EE06947601C85F1A27A2F76E45A6AA87")
		  key = DecodeHex("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")
		  nonce = DecodeHex("167DE44BB21980E7")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.Salsa20)
		  output = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		  
		  prefix = DecodeHex("F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71")
		  key = DecodeHex("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")
		  nonce = DecodeHex("0D74DB42A91077DE")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.Salsa20)
		  output = ks.DeriveKey(prefix.LenB, nonce)
		  Assert(libsodium.StrComp(prefix, output))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestKeyStream_XSalsa20()
		  ' xsalsa20 test vectors taken from https://www.apt-browse.org/browse/debian/jessie/main/amd64/libcrypto++-utils/5.6.1-6+deb8u2/file/usr/share/crypto++/TestVectors/salsa.txt
		  
		  Dim ciphertext As String = DecodeHex("b2af688e7d8fc4b508c05cc39dd583d6714322c64d7f3e63147aede2d9534934b04ff6f337b031815cd094bdbc6d7a92077dce709412286822ef0737ee47f6b7ffa22f9d53f11dd2b0a3bb9fc01d9a88f9d53c26e9365c2c3c063bc4840bfc812e4b80463e69d179530b25c158f543191cff993106511aa036043bbc75866ab7e34afc57e2cce4934a5faae6eabe4f221770183dd060467827c27a354159a081275a291f69d946d6fe28ed0b9ce08206cf484925a51b9498dbde178ddd3ae91a8581b91682d860f840782f6eea49dbb9bd721501d2c67122dea3b7283848c5f13e0c0de876bd227a856e4de593a3")
		  Dim plain As String = DecodeHex("093c5e5585579625337bd3ab619d615760d8c5b224a85b1d0efe0eb8a7ee163abb0376529fcc09bab506c618e13ce777d82c3ae9d1a6f972d4160287cbfe60bf2130fc0a6ff6049d0a5c8a82f429231f008082e845d7e189d37f9ed2b464e6b919e6523a8c1210bd52a02a4c3fe406d3085f5068d1909eeeca6369abc981a42e87fe665583f0ab85ae71f6f84f528e6b397af86f6917d9754b7320dbdc2fea81496f2732f532ac78c4e9c6cfb18f8e9bdf74622eb126141416776971a84f94d156beaf67aecbf2ad412e76e66e8fad7633f5b6d7f3d64b5c6c69ce29003c6024465ae3b89be78e915d88b4b5621d")
		  Dim key As libsodium.PKI.ForeignKey = DecodeHex("a6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff88030")
		  Dim nonce As String = DecodeHex("9e645a74e9e0a60d8243acd9177ab51a1beb8d5a2f5d700c")
		  Dim ks As New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.XSalsa20)
		  Dim output As String = ks.Process(plain, nonce)
		  Assert(libsodium.StrComp(ciphertext, output))
		  
		  ciphertext = DecodeHex("2c261a2f4e61a62e1b27689916bf03453fcbc97bb2af6f329391ef063b5a219bf984d07d70f602d85f6db61474e9d9f5a2deecb4fcd90184d16f3b5b5e168ee03ea8c93f3933a22bc3d1a5ae8c2d8b02757c87c073409052a2a8a41e7f487e041f9a49a0997b540e18621cad3a24f0a56d9b19227929057ab3ba950f6274b121f193e32e06e5388781a1cb57317c0ba6305e910961d01002f0")
		  plain = DecodeHex("feac9d54fc8c115ae247d9a7e919dd76cfcbc72d32cae4944860817cbdfb8c04e6b1df76a16517cd33ccf1acda9206389e9e318f5966c093cfb3ec2d9ee2de856437ed581f552f26ac2907609df8c613b9e33d44bfc21ff79153e9ef81a9d66cc317857f752cc175fd8891fefebb7d041e6517c3162d197e2112837d3bc4104312ad35b75ea686e7c70d4ec04746b52ff09c421451459fb59f")
		  key = DecodeHex("9e1da239d155f52ad37f75c7368a536668b051952923ad44f57e75ab588e475a")
		  nonce = DecodeHex("af06f17859dffa799891c4288f6635b5c5a45eee9017fd72")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.XSalsa20)
		  output = ks.Process(plain, nonce)
		  Assert(libsodium.StrComp(ciphertext, output))
		  
		  ciphertext = DecodeHex("27b8cfe81416a76301fd1eec6a4d99675069b2da2776c360db1bdfea7c0aa613913e10f7a60fec04d11e65f2d64e")
		  plain = DecodeHex("7758298c628eb3a4b6963c5445ef66971222be5d1a4ad839715d1188071739b77cc6e05d5410f963a64167629757")
		  key = DecodeHex("d5c7f6797b7e7e9c1d7fd2610b2abf2bc5a7885fb3ff78092fb3abe8986d35e2")
		  nonce = DecodeHex("744e17312b27969d826444640e9c4a378ae334f185369c95")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.XSalsa20)
		  output = ks.Process(plain, nonce)
		  Assert(libsodium.StrComp(ciphertext, output))
		  
		  ciphertext = DecodeHex("c815b6b79b64f9369aec8dce8c753df8a50f2bc97c70ce2f014db33a65ac5816bac9e30ac08bdded308c65cb87e28e2e71b677dc25c5a6499c1553555daf1f55270a56959dffa0c66f24e0af00951ec4bb59ccc3a6c5f52e0981647e53e439313a52c40fa7004c855b6e6eb25b212a138e843a9ba46edb2a039ee82a263abe")
		  plain = DecodeHex("d30a6d42dff49f0ed039a306bae9dec8d9e88366cc19e8c3642fd58fa0794ebf8029d949730339b0823a51f0f49f0d2c71f1051c1e0e2c86941f172789cdb1b0107413e70f982ff9761877bb526ef1c3eb1106a948d60ef21bd35d32cfd64f89b79ed63ecc5cca56246af736766f285d8e6b0da9cb1cd21020223ffacc5a32")
		  key = DecodeHex("760158da09f89bbab2c99e6997f9523a95fcef10239bcca2573b7105f6898d34")
		  nonce = DecodeHex("43636b2cc346fc8b7c85a19bf507bdc3dafe953b88c69dba")
		  ks = New libsodium.KeyStream(key, libsodium.KeyStream.StreamType.XSalsa20)
		  output = ks.Process(plain, nonce)
		  Assert(libsodium.StrComp(ciphertext, output))
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function TestName(Number As Integer) As String
		  Select Case Number
		  Case 1
		    Return "TestPKIEncrypt"
		  Case 2
		    Return "TestPKISign"
		  Case 3
		    Return "TestUtils"
		  Case 4
		    Return "TestPassword"
		  Case 5
		    Return "TestSecureMemory"
		  Case 6
		    Return "TestHash"
		  Case 7
		    Return "TestPKIForeignKey"
		  Case 8
		    Return "TestPKIExchange"
		  Case 9
		    Return "TestPKISeal"
		  Case 10
		    Return "TestSKIMAC"
		  Case 11
		    Return "TestKeyStream_ChaCha20"
		  Case 12
		    Return "TestKeyStream_Salsa20"
		  Case 13
		    Return "TestKeyStream_XSalsa20"
		  Else
		    Return "Unknown test"
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPassword()
		  Dim pass As New libsodium.Password(TestPasswordValue)
		  Const seckey = "74DD10A2050F3DB5FF7BE69F8DB08A26B70A129C96F370269BD409D6FE679997"
		  Const sigskey = "9D04B7F72E44E4B8394BB5CD0F7CF63F991FB72AEDC97CC787832D34113B8C80C2AC0CD48B07F6F8218E4FA335E3280152E9E0DC02AA25AF277779A3AB554C28"
		  Const sigpkey = "C2AC0CD48B07F6F8218E4FA335E3280152E9E0DC02AA25AF277779A3AB554C28"
		  Const pubkey = "2D8679E52C38E766A7F855C4D55DF1829902D0652DA59232C5A9372CE2408124"
		  Const privkey = "74DD10A2050F3DB5FF7BE69F8DB08A26B70A129C96F370269BD409D6FE679997"
		  Const argon2 = "246172676F6E326924763D3139246D3D33323736382C743D342C703D312462704F65326D64443962536D6C4259624334554A39772436796537644A544D414E733244444157384E794D6B596231684664596B6E3069366570337763614852374D"
		  Const scrypt = "24372443362E2E2E2E2F2E2E2E2E4E6C2F794D396A624D624277725467505437656548497A5749525267763977584E6755714E6E736B6C4633245948666938444C4C304F367864777374624F57756173757A7237686D784B2F4476794D6967457943594A44"
		  Const nonce = "263B2C42A510B1A24DB2193AB862A4D0D3703B3A81A79F00"
		  Const salt = "A5097CF3ED4581A29EABCE98C612C354"
		  
		  Assert(pass.VerifyHash(libsodium.DecodeHex(argon2), pass.ALG_ARGON2))
		  Assert(pass.VerifyHash(libsodium.DecodeHex(scrypt), pass.ALG_SCRYPT))
		  
		  Dim skey As libsodium.SKI.SecretKey
		  skey = skey.Import(TestSecretKey, pass)
		  
		  Assert(libsodium.StrComp(skey.Value, libsodium.DecodeHex(seckey)))
		  TestSKIEncrypt(skey)
		  Dim sigk As New libsodium.PKI.SigningKey(pass, libsodium.DecodeHex(salt))
		  
		  Assert(libsodium.StrComp(sigk.PrivateKey, libsodium.DecodeHex(sigskey)))
		  Assert(libsodium.StrComp(sigk.PublicKey, libsodium.DecodeHex(sigpkey)))
		  
		  Dim enck As New libsodium.PKI.EncryptionKey(pass, libsodium.DecodeHex(salt))
		  'Dim fo As String = libsodium.EncodeHex(enck.PrivateKey)
		  'Dim go As String = libsodium.EncodeHex(enck.PublicKey)
		  Assert(libsodium.StrComp(enck.PrivateKey, libsodium.DecodeHex(privkey)))
		  Assert(libsodium.StrComp(enck.PublicKey, libsodium.DecodeHex(pubkey)))
		  TestPKIEncrypt(enck, libsodium.DecodeHex(nonce))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKIEncrypt(SenderKey As libsodium.PKI.EncryptionKey = Nil, Nonce As MemoryBlock = Nil)
		  If SenderKey = Nil Then SenderKey = libsodium.PKI.EncryptionKey.Import(TestEncryptionKey, TestPasswordValue)
		  Dim recipkey As libsodium.PKI.EncryptionKey
		  recipkey = recipkey.Generate(recipkey.RandomSeed)
		  If nonce = Nil Then nonce = recipkey.RandomNonce
		  
		  Dim msg1 As String = "This is a test message."
		  Dim crypted As String = libsodium.PKI.EncryptData(msg1, recipkey.PublicKey, senderkey, nonce)
		  Dim msg2 As String = libsodium.PKI.DecryptData(crypted, senderkey.PublicKey, recipkey, nonce)
		  
		  Assert(msg1 = msg2)
		  
		  Dim sharedkey As New libsodium.PKI.SharedSecret(recipkey.PublicKey, senderkey)
		  crypted = libsodium.PKI.EncryptData(msg1, sharedkey, nonce)
		  msg2 = libsodium.PKI.DecryptData(crypted, sharedkey, nonce)
		  
		  Assert(msg1 = msg2)
		  
		  Dim msgs() As MemoryBlock
		  Dim n As MemoryBlock = nonce
		  For i As Integer = 0 To 10
		    n = libsodium.IncrementNonce(n)
		    Assert(n <> nonce)
		    Dim m As MemoryBlock = libsodium.PKI.EncryptData(msg1, recipkey.PublicKey, senderkey, n)
		    Assert(m <> Nil)
		    msgs.Append(m)
		  Next
		  
		  n = nonce
		  For i As Integer = 0 To UBound(msgs)
		    n = libsodium.IncrementNonce(n)
		    Assert(n <> nonce)
		    Assert(libsodium.PKI.DecryptData(msgs(i), senderkey.PublicKey, recipkey, n) = msg1)
		  Next
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKIExchange()
		  // These test vectors are from https://tools.ietf.org/html/rfc7748#section-6.1
		  Const ALICE_SK = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
		  Const ALICE_PK = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
		  Const BOB_SK = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
		  Const BOB_PK = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
		  Const BOB_ALICE_SECRET = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
		  
		  Dim alice As libsodium.PKI.EncryptionKey
		  alice = alice.Derive(DecodeHex(ALICE_SK))
		  Assert(alice.PublicKey = DecodeHex(ALICE_PK))
		  
		  Dim bob As libsodium.PKI.EncryptionKey
		  bob = bob.Derive(DecodeHex(BOB_SK))
		  Assert(bob.PublicKey = DecodeHex(BOB_PK))
		  
		  Dim shsk As New libsodium.PKI.SharedSecret(alice.PublicKey, bob)
		  Dim k As MemoryBlock = shsk.DeriveSharedSecret(alice.PublicKey, bob)
		  Assert(EncodeHex(k) = BOB_ALICE_SECRET)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKIForeignKey()
		  Dim SenderKey As libsodium.PKI.EncryptionKey
		  SenderKey = SenderKey.Import(TestEncryptionKey, TestPasswordValue)
		  Dim recipkey As New libsodium.PKI.ForeignKey(SenderKey.Generate(SenderKey.RandomSeed))
		  Dim nonce As MemoryBlock = SenderKey.RandomNonce
		  
		  Dim msg1 As MemoryBlock = "This is a test message."
		  Dim crypted As MemoryBlock = libsodium.PKI.EncryptData(msg1, recipkey, senderkey, nonce)
		  Dim msg2 As MemoryBlock = libsodium.PKI.DecryptData(crypted, recipkey, senderkey, nonce)
		  
		  Assert(msg1 = msg2)
		  
		  
		  Dim SignKey As libsodium.PKI.SigningKey
		  SignKey = SignKey.Generate'Import(TestSigningKey, TestPasswordValue)
		  Dim verkey As New libsodium.PKI.ForeignKey(SignKey)
		  
		  crypted = libsodium.PKI.SignData(msg1, SignKey)
		  msg2 = libsodium.PKI.VerifyData(crypted, verkey)
		  
		  Assert(msg1 = msg2)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKISeal()
		  Dim recipkey As libsodium.PKI.EncryptionKey
		  recipkey = recipkey.Generate(recipkey.RandomSeed)
		  
		  Dim msg1 As String = "This is a test message."
		  Dim sealed As String = libsodium.PKI.SealData(msg1, recipkey.PublicKey)
		  Dim msg2 As String = libsodium.PKI.UnsealData(sealed, recipkey)
		  
		  Assert(msg1 = msg2)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKISign()
		  Dim senderkey As libsodium.PKI.SigningKey
		  senderkey = senderkey.Import(TestSigningKey, TestPasswordValue)
		  Dim msg As MemoryBlock = "This is a test message."
		  Dim sig As MemoryBlock = libsodium.PKI.SignData(msg, senderkey)
		  Assert(libsodium.PKI.VerifyData(sig, senderkey.PublicKey) <> Nil)
		  
		  //These test vectors are from http://ed25519.cr.yp.to/python/sign.input
		  Dim f As FolderItem = App.ExecutableFile.Parent.Child("ed25519_test_vectors.txt")
		  If Not f.Exists Then Return
		  
		  Dim tis As TextInputStream = TextInputStream.Open(f)
		  Try
		    Do Until tis.EOF
		      Dim line As String = tis.ReadLine
		      Dim skey, pkey As MemoryBlock
		      skey = DecodeHex(NthField(line, ":", 1))
		      pkey = DecodeHex(NthField(line, ":", 2))
		      msg = DecodeHex(NthField(line, ":", 3))
		      sig = DecodeHex(NthField(line, ":", 4))
		      
		      Dim k As libsodium.PKI.SigningKey
		      k = k.Derive(skey)
		      Assert(k.PublicKey = pkey)
		      Assert(k.PrivateKey = skey)
		      Assert(libsodium.PKI.VerifyData(msg, New libsodium.PKI.ForeignKey(k), sig))
		    Loop
		  Finally
		    tis.Close
		  End Try
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSecureMemory()
		  Dim data As SecureMemoryBlock = "Hello, world!"
		  data = New SecureMemoryBlock(64)
		  data.ZeroFill
		  
		  data.BooleanValue(0) = True
		  Assert(data.BooleanValue(0))
		  data.ZeroFill
		  
		  data.ByteValue(0) = 123
		  Assert(data.ByteValue(0) = 123)
		  data.ZeroFill
		  
		  data.ColorValue(0, 32) = &cFFFFFF00
		  Assert(data.ColorValue(0, 32) = &cFFFFFF00)
		  data.ZeroFill
		  
		  data.CString(0) = "123"
		  Assert(data.CString(0) = "123")
		  data.ZeroFill
		  
		  data.CurrencyValue(0) = 123.456
		  Assert(data.CurrencyValue(0) = 123.456)
		  data.ZeroFill
		  
		  data.DoubleValue(0) = 123.456
		  Assert(data.DoubleValue(0) = 123.456)
		  data.ZeroFill
		  
		  data.Int16Value(0) = 123
		  Assert(data.Int16Value(0) = 123)
		  data.ZeroFill
		  
		  data.Int32Value(0) = 123
		  Assert(data.Int32Value(0) = 123)
		  data.ZeroFill
		  
		  data.Int64Value(0) = 123
		  Assert(data.Int64Value(0) = 123)
		  data.ZeroFill
		  
		  data.Long(0) = 123
		  Assert(data.Long(0) = 123)
		  data.ZeroFill
		  
		  data.PString(0) = "123"
		  Assert(data.PString(0) = "123")
		  data.ZeroFill
		  
		  data.SingleValue(0) = 123.4
		  Assert(data.SingleValue(0) > 123.39)
		  Assert(data.SingleValue(0) < 123.41)
		  data.ZeroFill
		  
		  data.StringValue(0, 5) = "123.4"
		  Assert(data.StringValue(0, 5) = "123.4")
		  data.ZeroFill
		  
		  data.UInt16Value(0) = 123
		  Assert(data.UInt16Value(0) = 123)
		  data.ZeroFill
		  
		  data.UInt32Value(0) = 123
		  Assert(data.UInt32Value(0) = 123)
		  data.ZeroFill
		  
		  data.UInt64Value(0) = 123
		  Assert(data.UInt64Value(0) = 123)
		  data.ZeroFill
		  
		  data.UInt8Value(0) = 123
		  Assert(data.UInt8Value(0) = 123)
		  data.ZeroFill
		  
		  data.WString(0) = "123"
		  Assert(data.WString(0) = "123")
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSKIEncrypt(SecretKey As libsodium.SKI.SecretKey = Nil, Nonce As MemoryBlock = Nil)
		  If SecretKey = Nil Then SecretKey = libsodium.SKI.SecretKey.Import(TestSecretKey, TestPasswordValue)
		  If Nonce = Nil Then nonce = SecretKey.RandomNonce
		  
		  Dim msg1 As String = "This is a test message."
		  Dim crypted As String = libsodium.SKI.EncryptData(msg1, SecretKey, nonce)
		  Dim msg2 As String = libsodium.SKI.DecryptData(crypted, SecretKey, nonce)
		  
		  Assert(msg1 = msg2)
		  
		  //these test vectors are from NaCl
		  Const secret_key = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
		  Const box_nonce = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
		  Const box_message = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"
		  Const box_ciphertext = "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5"
		  
		  SecretKey = SecretKey.Derive(DecodeHex(secret_key))
		  nonce = DecodeHex(box_nonce)
		  
		  msg1 = box_message
		  crypted = libsodium.SKI.EncryptData(msg1, SecretKey, nonce)
		  msg2 = libsodium.SKI.DecryptData(crypted, SecretKey, nonce)
		  
		  Assert(msg1 = msg2)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSKIMAC()
		  Dim key As libsodium.SKI.SecretKey
		  key = key.Import(TestSecretKey, TestPasswordValue)
		  
		  Dim msg As String = "This is a test message."
		  Dim sig As String = libsodium.SKI.GenerateMAC(msg, key)
		  Assert(libsodium.SKI.VerifyMAC(sig, msg, key))
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestUtils()
		  Dim msg As String = "This is a test message."
		  Dim hex As String = libsodium.EncodeHex(msg)
		  Assert(hex = EncodeHex(msg))
		  Assert(msg = DecodeHex(hex))
		  
		  Assert(libsodium.StrComp(msg, msg))
		  Assert(Not libsodium.StrComp(msg, ConvertEncoding(msg, Encodings.UTF16)))
		  Assert(Not libsodium.StrComp(msg, "adfsdfsdfsdf"))
		  
		  Dim m As MemoryBlock = DecodeHex("315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3")
		  Dim h As MemoryBlock = libsodium.SHA256("Hello, world!")
		  Assert(h = m)
		  
		  m = DecodeHex("c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421")
		  h = libsodium.SHA512("Hello, world!")
		  Assert(h = m)
		  
		  Dim n As MemoryBlock = libsodium.PKI.EncryptionKey.RandomNonce
		  Assert(libsodium.CompareNonce(n, libsodium.IncrementNonce(n)) <> 0)
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected Failures() As Integer
	#tag EndProperty


	#tag Constant, Name = TestEncryptionKey, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PRIVATE KEY BLOCK-----\r#Salt\x3D9A2F4F3B4FAFFD84B678DA1351F1945A\r#Nonce\x3DA2EF9B28D9158FA45C77E7433F4D0F7FE0610EBAD3995E65\r#Limits\x3DInteractive\r\r027E4075A13783119AD8A295A8B8E02B47272AA5CD92E8C0BF3E9307E26BC810\rADD8F057F9B09321BB56F29E8C666715\r-----END CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = TestPasswordValue, Type = String, Dynamic = False, Default = \"SeeKritPassW0rd111", Scope = Private
	#tag EndConstant

	#tag Constant, Name = TestSecretKey, Type = String, Dynamic = False, Default = \"-----BEGIN XSALSA20 KEY BLOCK-----\r#Salt\x3D8D3043931703C32FC8C06365BD79744F\r#Nonce\x3D8941A0DA50BD3A4B052F00D9C19EE33C82324CD84472CCE8\r#Limits\x3DInteractive\r\r0044CC1757A6B07E1351FD569B80B75DE7A7245870679EA71E3E8CE2F7B8DC31\r6613D689444875717E19255D72F948B9\r-----END XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = TestSigningKey, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PRIVATE KEY BLOCK-----\r#Salt\x3D7C54516245BED05507819E0CE2B5BF9F\r#Nonce\x3D5ED36D5D5FD12993B0692C0279E42504D3373FB1893FF1EA\r#Limits\x3DInteractive\r\r1DADAD33D29A6F2FC654812F457489BDF4C22DF123AB7990CE56019E1BF26B25\rD62ED6D6EC3E059C32AD5DD8AE91DD2118B4E65CF791FB90045E1F633CD082FD\rD12C33FCEB77E965C17AB44C15D00308\r-----END ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant


	#tag ViewBehavior
		#tag ViewProperty
			Name="Index"
			Visible=true
			Group="ID"
			InitialValue="-2147483648"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Left"
			Visible=true
			Group="Position"
			InitialValue="0"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Name"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Super"
			Visible=true
			Group="ID"
			InheritedFrom="Object"
		#tag EndViewProperty
		#tag ViewProperty
			Name="Top"
			Visible=true
			Group="Position"
			InitialValue="0"
			InheritedFrom="Object"
		#tag EndViewProperty
	#tag EndViewBehavior
End Module
#tag EndModule
