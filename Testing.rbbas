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
		  
		  Return UBound(Failures) = -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestHash()
		  Const key = "27F2B73F7A94144A7F459792892D2CFFB78FB442FE64D451EDB63B08DA940C27"
		  Const hash = "2D4B92842EACAE0B7B3804FC70092CB0A1D09691D12AC8477B58D36701F1C79926FE8DC8397CC54CB5013BA024A037DDBAB3EE6BB2F1863779A4BD6AA0515068"
		  
		  Assert(EncodeHex(libsodium.GenericHash("Hello, world!", DecodeHex(key))) = hash)
		  
		  Assert(libsodium.EncodeHex(libsodium.SHA256("Hello, world!")) = "315F5BDB76D078C43B8AC0064E4A0164612B1FCE77C869345BFC94C75894EDD3")
		  Assert(libsodium.EncodeHex(libsodium.SHA512("Hello, world!")) = "C1527CD893C124773D811911970C8FE6E857D6DF5DC9226BD8A160614C0CD963A4DDEA2B94BB7D36021EF9D865D5CEA294A82DD49A0BB269F51F6E7A57F79421")
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPassword()
		  Dim pass As New libsodium.Password(TestPasswordValue)
		  Const seckey = "74DD10A2050F3DB5FF7BE69F8DB08A26B70A129C96F370269BD409D6FE679997"
		  Const sigskey = "9D04B7F72E44E4B8394BB5CD0F7CF63F991FB72AEDC97CC787832D34113B8C80C2AC0CD48B07F6F8218E4FA335E3280152E9E0DC02AA25AF277779A3AB554C28"
		  Const sigpkey = "C2AC0CD48B07F6F8218E4FA335E3280152E9E0DC02AA25AF277779A3AB554C28"
		  Const pubkey = "2D8679E52C38E766A7F855C4D55DF1829902D0652DA59232C5A9372CE2408124"
		  Const privkey = "74DD10A2050F3DB5FF7BE69F8DB08A26B70A129C96F370269BD409D6FE679997"
		  Const argon2 = "246172676F6E326924763D31392C6D3D33323736382C743D342C703D31244D6554384445353145506151474243485833596E4D512454316D5843496172675A6547514242766B4D3546446367526848616339755A50616B626A573541424B3077"
		  Const scrypt = "24372443362E2E2E2E2F2E2E2E2E714945592F755539347150553161666D77554D5730304F4A43336C74592E6A335373426C79446D57566239247A37345A697579536C5465346C50544A765478435234675542743231514C784C62427943586364354F7132"
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
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKIForeignKey()
		  Dim SenderKey As libsodium.PKI.EncryptionKey
		  SenderKey = SenderKey.Import(TestEncryptionKey, TestPasswordValue)
		  Dim recipkey As New libsodium.PKI.ForeignKey(SenderKey.Generate(SenderKey.RandomSeed))
		  Dim nonce As MemoryBlock = SenderKey.RandomNonce
		  
		  Dim msg1 As String = "This is a test message."
		  Dim crypted As String = libsodium.PKI.EncryptData(msg1, recipkey, senderkey, nonce)
		  Dim msg2 As String = libsodium.PKI.DecryptData(crypted, recipkey, senderkey, nonce)
		  
		  Assert(msg1 = msg2)
		  
		  
		  Dim SignKey As libsodium.PKI.SigningKey
		  SignKey = SignKey.Import(TestSigningKey, TestPasswordValue)
		  Dim verkey As New libsodium.PKI.ForeignKey(SignKey.Generate(SenderKey.RandomSeed))
		  
		  crypted = libsodium.PKI.SignData(msg1, SignKey)
		  msg2 = libsodium.PKI.VerifyData(crypted, verkey)
		  
		  Assert(msg1 = msg2)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKISign()
		  Dim senderkey As libsodium.PKI.SigningKey
		  senderkey = senderkey.Import(GetOpenFolderItem(""), TestPasswordValue)
		  Dim msg As MemoryBlock = "This is a test message."
		  Dim sig As MemoryBlock = libsodium.PKI.SignData(msg, senderkey)
		  Assert(libsodium.PKI.VerifyData(sig, senderkey.PublicKey) <> Nil)
		  
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
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected Failures() As Integer
	#tag EndProperty


	#tag Constant, Name = TestEncryptionKey, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----\r\rLYZ55Sw452an+FXE1V3xgpkC0GUtpZIyxak3LOJAgSQ\x3D\r-----END CURVE25519 PUBLIC KEY BLOCK-----\r-----BEGIN CURVE25519 PRIVATE KEY BLOCK-----\r#Salt\x3Dmi9PO0+v/YS2eNoTUfGUWg\x3D\x3D\r#Nonce\x3Dou+bKNkVj6Rcd+dDP00Pf+BhDrrTmV5l\r#Limits\x3DInteractive\r\rAn5AdaE3gxGa2KKVqLjgK0cnKqXNkujAvz6TB+JryBCt2PBX+bCTIbtW8p6MZmcV\r-----END CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = TestPasswordValue, Type = String, Dynamic = False, Default = \"SeeKritPassW0rd111", Scope = Private
	#tag EndConstant

	#tag Constant, Name = TestSecretKey, Type = String, Dynamic = False, Default = \"-----BEGIN XSALSA20 KEY BLOCK-----\r#Salt\x3DjTBDkxcDwy/IwGNlvXl0Tw\x3D\x3D\r#Nonce\x3DiUGg2lC9OksFLwDZwZ7jPIIyTNhEcszo\r#Limits\x3DInteractive\r\rAETMF1emsH4TUf1Wm4C3XeenJFhwZ56nHj6M4ve43DFmE9aJREh1cX4ZJV1y+Ui5\r-----END XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = TestSigningKey, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PUBLIC KEY BLOCK-----\r\rwqwM1IsH9vghjk+jNeMoAVLp4NwCqiWvJ3d5o6tVTCg\x3D\r-----END ED25519 PUBLIC KEY BLOCK-----\r-----BEGIN ED25519 PRIVATE KEY BLOCK-----\r#Salt\x3Df+C0Jejbwhwfyhh4txF9Ww\x3D\x3D\r#Nonce\x3DHEKurwUaMM0tPyP3AeXpXiXI+LDewWwl\r#Limits\x3DInteractive\r\rX5OoL1S1anFshbOHNK4dhj4McnP6WiRL3lU5DMXbd2ScFOB+OFZ+EZV30fcN5fDKZpNgGKnfxmdh\r9RHdAozkwW3SFqti1FC6wUyA0TLzQm4\x3D\r-----END ED25519 PRIVATE KEY BLOCK-----", Scope = Private
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
