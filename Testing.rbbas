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
		  Const scrypt = "24372443362E2E2E2E2F2E2E2E2E367458754A5A794D6A59387A4A6351626B7171504B5548734743644C4E70676D523968737169314458712F247772485472494374684A2E6E6539544367704665565A716E7942734378667A51514A387A314F4F7A643442"
		  Const seckey = "0C668BDF5DEB049832079A064A5F8D7D5B358FC64855EE9A4BB6F4A011ED764C"
		  Const pubkey = "657C3FC03DBD12EF25E51B6AAB082C8A3C041466144AE265DC3904D0B40D9131"
		  Const privkey = "CA220B8A84880C290EFBA7F5D8C25637E7C47B05AC88FF98AC881F73781E6E20"
		  
		  'Dim skey As New libsodium.SKI.SecretKey(pass)
		  'Assert(libsodium.StrComp(skey.Value, libsodium.DecodeHex(seckey)))
		  
		  'Dim sigk As New libsodium.PKI.SigningKey(pass)
		  'Assert(libsodium.StrComp(sigk.PrivateKey, libsodium.DecodeHex(privkey)))
		  'Assert(libsodium.StrComp(sigk.PublicKey, libsodium.DecodeHex(pubkey)))
		  
		  Dim enck As New libsodium.PKI.EncryptionKey(pass)
		  Dim fo As String = libsodium.EncodeHex(enck.PrivateKey)
		  Dim go As String = libsodium.EncodeHex(enck.PublicKey)
		  Assert(libsodium.StrComp(enck.PrivateKey, libsodium.DecodeHex(privkey)))
		  Assert(libsodium.StrComp(enck.PublicKey, libsodium.DecodeHex(pubkey)))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestPKIEncrypt()
		  Dim senderkey As libsodium.PKI.EncryptionKey = libsodium.PKI.EncryptionKey.Generate()
		  Dim recipkey As libsodium.PKI.EncryptionKey = libsodium.PKI.EncryptionKey.Derive(libsodium.PKI.RandomEncryptionKey)
		  Dim nonce As MemoryBlock = libsodium.PKI.RandomNonce
		  
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
		  Dim nonce As MemoryBlock = libsodium.SKI.RandomNonce
		  
		  Dim msg1 As String = "This is a test message."
		  Dim crypted As String = libsodium.SKI.EncryptData(msg1, key, nonce)
		  Dim msg2 As String = libsodium.SKI.DecryptData(crypted, key, nonce)
		  
		  Assert(msg1 = msg2)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub TestSKIMAC()
		  Dim key As libsodium.SKI.SecretKey = libsodium.SKI.RandomKey()
		  
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
