#tag Module
Protected Module Exporting
	#tag Method, Flags = &h1
		Protected Sub AssertType(KeyData As MemoryBlock, ExpectedType As libsodium.ExportableType)
		  Dim detect As ExportableType = GetType(KeyData)
		  If Not IsValidFormat(KeyData, detect) Then Raise New SodiumException(ERR_IMPORT_INVALID)
		  If detect <> ExpectedType Then Raise New SodiumException(ERR_KEYTYPE_MISMATCH)
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecodeMessage(BinaryMessage As MemoryBlock) As MemoryBlock
		  Dim n As MemoryBlock
		  Return DecodeMessage(BinaryMessage, n)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecodeMessage(EncodedMessage As MemoryBlock, ByRef NonceValue As MemoryBlock) As MemoryBlock
		  ' This method takes data encoded in the plain text format generated by the EncodeMessage method
		  ' and returns the raw binary data of the message. If the message contains an embedded nonce then
		  ' the Nonce parameter will be modified to point to the nonce value.
		  
		  Dim t As ExportableType = GetType(EncodedMessage)
		  Dim metadata As Dictionary = GetMetaData(EncodedMessage)
		  EncodedMessage = GetKeyData(EncodedMessage, t)
		  NonceValue = metadata.Lookup("Nonce", Nil)
		  Return EncodedMessage
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncodeMessage(BinaryMessage As MemoryBlock, Optional Nonce As MemoryBlock) As MemoryBlock
		  ' This method takes a raw binary message and encodes it in a plain text
		  ' format that is suitable to be stored or transferred. If a Nonce is
		  ' specified then then the message was encrypted using the nonce and the 
		  ' nonce is encoded in the return value.
		  
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  output.Write(GetPrefix(ExportableType.Unknown) + EndOfLine.Windows)
		  If Nonce <> Nil Then
		    output.Write("#Nonce=")
		    output.Write(libsodium.EncodeHex(nonce))
		    output.Write(EndOfLine.Windows)
		  End If
		  output.Write(EndOfLine.Windows)
		  BinaryMessage = libsodium.EncodeHex(BinaryMessage)
		  Dim bs As New BinaryStream(BinaryMessage)
		  Do
		    output.Write(bs.Read(64) + EndOfLine.Windows)
		  Loop Until bs.EOF
		  output.Write(GetSuffix(ExportableType.Unknown) + EndOfLine.Windows)
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Export(KeyData As MemoryBlock, Type As libsodium.ExportableType, Optional Passwd As libsodium.Password, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Moderate, Optional MetaData As Dictionary) As MemoryBlock
		  ' This method takes a raw binary crypto key and encodes it in a plain text
		  ' format that is suitable to be stored or transferred. If a Password is
		  ' specified then then key will be encrypted with a random nonce and a secret
		  ' key derived from the password and a random salt; this password will be
		  ' needed to import the key again. The salt and nonce will be encoded in the
		  ' exported data along with any additional data in the optional MetaData
		  ' dictionary. The keys and values in the dictionary must all be strings.
		  
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  output.Write(GetPrefix(Type) + EndOfLine.Windows)
		  
		  If Passwd <> Nil Then
		    Dim salt As MemoryBlock = Passwd.RandomSalt
		    Dim sk As New libsodium.SKI.SecretKey(Passwd, salt, Limits)
		    Dim nonce As MemoryBlock = sk.RandomNonce
		    KeyData = libsodium.SKI.EncryptData(KeyData, sk, nonce)
		    output.Write("#Salt=")
		    output.Write(libsodium.EncodeHex(salt))
		    output.Write(EndOfLine.Windows)
		    output.Write("#Nonce=")
		    output.Write(libsodium.EncodeHex(nonce))
		    output.Write(EndOfLine.Windows)
		    Select Case PBKDF_ALG
		    Case Passwd.ALG_ARGON2
		      output.Write("#Alg=Argon2" + EndOfLine.Windows)
		    Case Passwd.ALG_SCRYPT
		      output.Write("#Alg=scrypt" + EndOfLine.Windows)
		    End Select
		    Select Case Limits
		    Case ResourceLimits.Interactive
		      output.Write("#Limits=Interactive" + EndOfLine.Windows)
		    Case ResourceLimits.Moderate
		      output.Write("#Limits=Moderate" + EndOfLine.Windows)
		    Case ResourceLimits.Sensitive
		      output.Write("#Limits=Sensitive" + EndOfLine.Windows)
		    End Select
		  End If
		  If MetaData <> Nil Then
		    For Each name As String In MetaData.Keys
		      output.Write("#" + name + "=" + MetaData.Value(name) + EndOfLine.Windows)
		    Next
		  End If
		  output.Write(EndOfLine.Windows)
		  KeyData = libsodium.EncodeHex(KeyData)
		  Dim bs As New BinaryStream(KeyData)
		  Do
		    output.Write(bs.Read(64) + EndOfLine.Windows)
		  Loop Until bs.EOF
		  output.Write(GetSuffix(Type) + EndOfLine.Windows)
		  
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetKeyData(EncodedKey As MemoryBlock, Type As libsodium.ExportableType) As MemoryBlock
		  EncodedKey = ReplaceLineEndings(EncodedKey, EndOfLine.Windows)
		  Dim lines() As String = SplitB(EncodedKey, EndOfLine.Windows)
		  Dim suffix As String = GetSuffix(Type)
		  Dim prefix As String = GetPrefix(Type)
		  
		  Dim i As Integer
		  Do Until Ubound(lines) <= i Or lines(i) = Prefix
		    i = i + 1
		  Loop
		  If i = UBound(lines) Then Return Nil
		  
		  Dim key As New MemoryBlock(0)
		  Dim output As New BinaryStream(key)
		  For i = i + 1 To UBound(lines)
		    Dim s As String = lines(i)
		    Select Case True
		    Case Left(s, 1) = "#", s.Trim = "" ' comment/blank line
		      Continue
		    Case s = Suffix
		      Exit For
		    Else
		      output.Write(s.Trim)
		    End Select
		  Next
		  output.Close
		  Return libsodium.DecodeHex(REALbasic.Trim(key))
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetMetaData(EncodedKey As MemoryBlock) As Dictionary
		  EncodedKey = ReplaceLineEndings(EncodedKey, EndOfLine.Windows)
		  Dim lines() As String = SplitB(EncodedKey, EndOfLine.Windows)
		  Dim MetaData As New Dictionary
		  For i As Integer = 0 To UBound(lines)
		    Dim s As String = lines(i)
		    If Left(s, 1) = "#" Then ' meta line
		      Select Case True
		      Case Left(s, 6) = "#Salt="
		        MetaData.Value("Salt") = libsodium.DecodeHex(Right(s, s.Len - 6))
		      Case Left(s, 7) = "#Nonce="
		        MetaData.Value("Nonce") = libsodium.DecodeHex(Right(s, s.Len - 7))
		      Case Left(s, 5) = "#Alg="
		        Select Case Right(s, s.Len - 5)
		        Case "Argon2"
		          MetaData.Value("Alg") = Password.ALG_ARGON2
		        Case "scrypt"
		          MetaData.Value("Alg") = Password.ALG_SCRYPT
		        Else
		          s = Replace(s, NthField(s, "=", 1) + "=", "")
		          MetaData.Value("Alg") = s
		        End Select
		      Case Left(s, 8) = "#Limits="
		        Select Case Right(s, s.Len - 8)
		        Case "Interactive"
		          MetaData.Value("Limits") = ResourceLimits.Interactive
		        Case "Moderate"
		          MetaData.Value("Limits") = ResourceLimits.Moderate
		        Case "Sensitive"
		          MetaData.Value("Limits") = ResourceLimits.Sensitive
		        End Select
		      Else
		        If InStr(s, "=") > 0 Then
		          Dim n As String = NthField(s, "=", 1)
		          s = Replace(s, n + "=", "")
		          MetaData.Value(n) = s
		        Else
		          MetaData.Value(s) = ""
		        End If
		      End Select
		    End If
		  Next
		  
		  Return MetaData
		  
		Exception
		  Return Nil
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetPrefix(Type As libsodium.ExportableType) As String
		  Select Case Type
		  Case ExportableType.CryptPrivate
		    Return EncryptionPrivatePrefix
		    
		  Case ExportableType.CryptPublic
		    Return EncryptionPublicPrefix
		    
		  Case ExportableType.SignPrivate
		    Return SigningPrivatePrefix
		    
		  Case ExportableType.SignPublic
		    Return SigningPublicPrefix
		    
		  Case ExportableType.SharedSecret
		    Return SharedPrefix
		    
		  Case ExportableType.Secret
		    Return SalsaPrefix
		    
		  Case ExportableType.Signature
		    Return SignaturePrefix
		    
		  Case ExportableType.HMAC
		    Return HMACPrefix
		    
		  Case ExportableType.StateHeader
		    Return StateHeaderPrefix
		    
		  Case ExportableType.SignatureDigest
		    Return SignatureDigestPrefix
		    
		  Else
		    Return UnknownPrefix
		    
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetSuffix(Type As libsodium.ExportableType) As String
		  Select Case Type
		  Case ExportableType.CryptPrivate
		    Return EncryptionPrivateSuffix
		    
		  Case ExportableType.CryptPublic
		    Return EncryptionPublicSuffix
		    
		  Case ExportableType.SignPrivate
		    Return SigningPrivateSuffix
		    
		  Case ExportableType.SignPublic
		    Return SigningPublicSuffix
		    
		  Case ExportableType.SharedSecret
		    Return SharedSuffix
		    
		  Case ExportableType.Secret
		    Return SalsaSuffix
		    
		  Case ExportableType.Signature
		    Return SignatureSuffix
		    
		  Case ExportableType.HMAC
		    Return HMACSuffix
		    
		  Case ExportableType.StateHeader
		    Return StateHeaderSuffix
		    
		  Case ExportableType.SignatureDigest
		    Return SignatureDigestSuffix
		    
		  Else
		    Return UnknownSuffix
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GetType(EncodedKey As MemoryBlock) As libsodium.ExportableType
		  Static Prefixes() As String = Array(EncryptionPrivatePrefix, EncryptionPublicPrefix, _
		  SigningPrivatePrefix, SigningPublicPrefix, SalsaPrefix, SharedPrefix, SignaturePrefix, HMACPrefix, StateHeaderPrefix, _
		  SignatureDigestPrefix)
		  Dim ExportedKey As MemoryBlock = ReplaceLineEndings(EncodedKey, EndOfLine.Windows)
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  For i As Integer = 0 To UBound(lines)
		    Select Case Prefixes.IndexOf(lines(i))
		    Case 0 'PKE private
		      Return ExportableType.CryptPrivate
		    Case 1 'PKE public
		      Return ExportableType.CryptPublic
		    Case 2 'PKS private
		      Return ExportableType.SignPrivate
		    Case 3 'PKS public
		      Return ExportableType.SignPublic
		    Case 4 'Secret key
		      Return ExportableType.Secret
		    Case 5 'Shared secret
		      Return ExportableType.SharedSecret
		    Case 6 'Signature
		      Return ExportableType.Signature
		    Case 7 'MAC
		      Return ExportableType.HMAC
		    Case 8 ' decryption header
		      Return ExportableType.StateHeader
		    Case 9 ' Signed hash digest
		      Return ExportableType.SignatureDigest
		    End Select
		  Next
		  Return ExportableType.Unknown
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Import(EncodedKey As MemoryBlock, ByRef Metadata As Dictionary, Optional Passwd As libsodium.Password) As MemoryBlock
		  ' This method takes a key encoded in the plain text format generated by the Export method
		  ' and returns the raw binary data of the key. If a Password is specified then the key will
		  ' be decrypted with a SecretKey derived from the password.
		  
		  Metadata = GetMetaData(EncodedKey)
		  EncodedKey = GetKeyData(EncodedKey, GetType(EncodedKey))
		  If Metadata.HasKey("Nonce") And Metadata.HasKey("Salt") And Metadata.HasKey("Limits") Then
		    If Passwd = Nil Then Raise New SodiumException(ERR_IMPORT_ENCRYPTED)
		    Dim n As MemoryBlock = Metadata.Value("Nonce")
		    Dim s As MemoryBlock = Metadata.Value("Salt")
		    Dim l As ResourceLimits = Metadata.Value("Limits")
		    Dim a As Int32 = Metadata.Lookup("Alg", PBKDF_ALG)
		    
		    Dim sk As New libsodium.SKI.SecretKey(Passwd, s, l, a)
		    EncodedKey = libsodium.SKI.DecryptData(EncodedKey, sk, n)
		    If EncodedKey = Nil Then Raise New SodiumException(ERR_IMPORT_PASSWORD)
		  End If
		  
		  Return EncodedKey
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Import(EncodedKey As MemoryBlock, Optional Passwd As libsodium.Password) As MemoryBlock
		  ' This method takes a key encoded in the plain text format generated by the Export method
		  ' and returns the raw binary data of the key. If a Password is specified then the key will
		  ' be decrypted with a SecretKey derived from the password.
		  
		  Dim metadata As Dictionary
		  Return Import(EncodedKey, metadata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function IsValidFormat(EncodedKey As MemoryBlock, DetectedFormat As ExportableType) As Boolean
		  EncodedKey = ReplaceLineEndings(EncodedKey, EndOfLine.Windows).Trim
		  Dim lines() As String = SplitB(EncodedKey, EndOfLine.Windows)
		  If UBound(lines) < 2 Then Return False
		  If lines(lines.Ubound) = "" Then Return False
		  Return lines(lines.Ubound) = GetSuffix(DetectedFormat)
		  
		Exception
		  Return False
		End Function
	#tag EndMethod


	#tag Constant, Name = EncryptionPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = EncryptionPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = EncryptionPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = EncryptionPublicSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = HMACPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN POLY1305 MAC BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = HMACSuffix, Type = String, Dynamic = False, Default = \"-----END POLY1305 MAC BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = MessagePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = MessageSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = NoncePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 NONCE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = NonceSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 NONCE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = PBKDF_ALG, Type = Double, Dynamic = False, Default = \"libsodium.Password.ALG_ARGON2", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SalsaPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SalsaSuffix, Type = String, Dynamic = False, Default = \"-----END XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SharedPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 SHARED KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SharedSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 SHARED KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SignatureDigestPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519ph SIGNATURE BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SignatureDigestSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519ph SIGNATURE BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SignaturePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 SIGNATURE BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SignatureSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 SIGNATURE BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPublicSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = StateHeaderPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN STATE HEADER-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = StateHeaderSuffix, Type = String, Dynamic = False, Default = \"-----END STATE HEADER-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = UnknownPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN DATA BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = UnknownSuffix, Type = String, Dynamic = False, Default = \"-----END DATA BLOCK-----", Scope = Private
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
