#tag Module
Protected Module Testing
	#tag Method, Flags = &h21
		Private Sub Assert(b As Boolean)
		  If Not b Then Raise New RuntimeException
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RunTests() As Boolean
		  TestResult = 0
		  Try
		    TestPKIEncrypt()
		  Catch
		    TestResult = 1
		    Return False
		  End Try
		  
		  Try
		    TestPKISign()
		  Catch
		    TestResult = 2
		    Return False
		  End Try
		  
		  Try
		    TestPKIOther()
		  Catch
		    TestResult = 3
		    Return False
		  End Try
		  
		  Try
		    TestPassword()
		  Catch
		    TestResult = 4
		    Return False
		  End Try
		  
		  'Try
		  'TestCookieEngine()
		  'Catch
		  'TestResult = 5
		  'Return False
		  'End Try
		  
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPassword()
		  Dim pass As New libsodium.Password("SeeKritPassW0rd111")
		  Const argon2 = "246172676F6E326924763D31392C6D3D33323736382C743D342C703D31244D6554384445353145506151474243485833596E4D512454316D5843496172675A6547514242766B4D3546446367526848616339755A50616B626A573541424B3077"
		  Const scrypt = "24372443362E2E2E2E2F2E2E2E2E714945592F755539347150553161666D77554D5730304F4A43336C74592E6A335373426C79446D57566239247A37345A697579536C5465346C50544A765478435234675542743231514C784C62427943586364354F7132"
		  Const seckey = "74DD10A2050F3DB5FF7BE69F8DB08A26B70A129C96F370269BD409D6FE679997"
		  Const sigskey = "9D04B7F72E44E4B8394BB5CD0F7CF63F991FB72AEDC97CC787832D34113B8C80C2AC0CD48B07F6F8218E4FA335E3280152E9E0DC02AA25AF277779A3AB554C28"
		  Const sigpkey = "C2AC0CD48B07F6F8218E4FA335E3280152E9E0DC02AA25AF277779A3AB554C28"
		  Const pubkey = "2D8679E52C38E766A7F855C4D55DF1829902D0652DA59232C5A9372CE2408124"
		  Const privkey = "74DD10A2050F3DB5FF7BE69F8DB08A26B70A129C96F370269BD409D6FE679997"
		  Const nonce = "263B2C42A510B1A24DB2193AB862A4D0D3703B3A81A79F00"
		  Const salt = "A5097CF3ED4581A29EABCE98C612C354"
		  
		  Assert(pass.VerifyHash(libsodium.DecodeHex(argon2), pass.ALG_ARGON2))
		  Assert(pass.VerifyHash(libsodium.DecodeHex(scrypt), pass.ALG_SCRYPT))
		  
		  Dim skey As New libsodium.SKI.SecretKey(pass, libsodium.DecodeHex(salt))
		  Assert(libsodium.StrComp(skey.Value, libsodium.DecodeHex(seckey)))
		  
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
		  If SenderKey = Nil Then SenderKey = libsodium.PKI.EncryptionKey.Generate()
		  Dim recipkey As libsodium.PKI.EncryptionKey
		  recipkey = recipkey.Derive(recipkey.RandomPrivateKey)
		  If nonce = Nil Then nonce = recipkey.RandomNonce
		  
		  Dim msg1 As String = "This is a test message."
		  Dim crypted As String = libsodium.PKI.EncryptData(msg1, recipkey.PublicKey, senderkey, nonce)
		  Dim msg2 As String = libsodium.PKI.DecryptData(crypted, senderkey.PublicKey, recipkey, nonce)
		  
		  Assert(msg1 = msg2)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKIOther()
		  Dim msg As String = "This is a test message."
		  Dim hex As String = libsodium.EncodeHex(msg)
		  Assert(hex = EncodeHex(msg))
		  Assert(msg = DecodeHex(hex))
		  
		  Assert(libsodium.StrComp(msg, msg))
		  Assert(Not libsodium.StrComp(msg, ConvertEncoding(msg, Encodings.UTF16)))
		  Assert(Not libsodium.StrComp(msg, "adfsdfsdfsdf"))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKISign()
		  Dim senderkey As libsodium.PKI.SigningKey = libsodium.PKI.SigningKey.Generate()
		  
		  Dim msg As String = "This is a test message."
		  Dim sig As String = libsodium.PKI.SignData(msg, senderkey)
		  Assert(libsodium.PKI.VerifyData(sig, senderkey.PublicKey))
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSKIEncrypt()
		  Dim key As libsodium.SKI.SecretKey = libsodium.SKI.SecretKey.Generate()
		  Dim nonce As MemoryBlock = key.RandomNonce
		  
		  Dim msg1 As String = "This is a test message."
		  Dim crypted As String = libsodium.SKI.EncryptData(msg1, key, nonce)
		  Dim msg2 As String = libsodium.SKI.DecryptData(crypted, key, nonce)
		  
		  Assert(msg1 = msg2)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSKIMAC()
		  Dim key As libsodium.SKI.SecretKey
		  key = key.Generate()
		  
		  Dim msg As String = "This is a test message."
		  Dim sig As String = libsodium.SKI.GenerateMAC(msg, key)
		  Assert(libsodium.SKI.VerifyMAC(sig, msg, key))
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSKIOther()
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
		Protected TestResult As Integer
	#tag EndProperty


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
