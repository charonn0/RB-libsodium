#tag Module
Protected Module Exporting
	#tag Method, Flags = &h1
		Protected Function Export(KeyData As MemoryBlock, Type As libsodium.Exporting.ExportableType, Optional Passwd As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, Optional MetaData As Dictionary) As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  Dim ExportedKey As MemoryBlock
		  output.Write(GetPrefix(Type) + EndOfLine.Windows)
		  
		  If Passwd <> Nil Then
		    If salt = Nil Then salt = Passwd.RandomSalt
		    Dim key As libsodium.SKI.SecretKey
		    Dim nonce As MemoryBlock = key.RandomNonce
		    key = New libsodium.SKI.SecretKey(Passwd, salt, Limits)
		    ExportedKey = libsodium.SKI.EncryptData(KeyData, key, nonce)
		    output.Write("#Salt=")
		    output.Write(libsodium.EncodeHex(salt))
		    output.Write(EndOfLine.Windows)
		    output.Write("#Nonce=")
		    output.Write(libsodium.EncodeHex(nonce))
		    output.Write(EndOfLine.Windows)
		    Select Case Limits
		    Case ResourceLimits.Interactive
		      output.Write("#Limits=Interactive" + EndOfLine.Windows)
		    Case ResourceLimits.Moderate
		      output.Write("#Limits=Moderate" + EndOfLine.Windows)
		    Case ResourceLimits.Sensitive
		      output.Write("#Limits=Sensitive" + EndOfLine.Windows)
		    End Select
		  Else
		    ExportedKey = KeyData
		  End If
		  If MetaData <> Nil Then
		    For Each Key As String In MetaData.Keys
		      output.Write("#" + Key + "=" + MetaData.Value(Key) + EndOfLine.Windows)
		    Next
		  End If
		  output.Write(EndOfLine.Windows)
		  ExportedKey = libsodium.EncodeHex(ExportedKey)
		  Dim bs As New BinaryStream(ExportedKey)
		  Do
		    output.Write(bs.Read(64) + EndOfLine.Windows)
		  Loop Until bs.EOF
		  output.Write(GetSuffix(Type) + EndOfLine.Windows)
		  
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetKeyData(EncodedKey As MemoryBlock, Type As libsodium.Exporting.ExportableType) As MemoryBlock
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
		  Return libsodium.DecodeHex(key.Trim)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GetMetaData(EncodedKey As MemoryBlock) As Dictionary
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
		      Case Left(s, 8) = "#Limits="
		        Select Case Right(s, s.Len - 8)
		        Case "Interactive"
		          MetaData.Value("Limits") = ResourceLimits.Interactive
		        Case "Moderate"
		          MetaData.Value("Limits") = ResourceLimits.Moderate
		        Case "Sensitive"
		          MetaData.Value("Limits") = ResourceLimits.Sensitive
		        Else
		          Dim n As String = NthField(s, "=", 1)
		          s = Replace(s, n + "=", "")
		          MetaData.Value(n) = s
		        End Select
		      End Select
		    End If
		  Next
		  
		  Return MetaData
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetPrefix(Type As libsodium.Exporting.ExportableType) As String
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
		  Else
		    Return SalsaPrefix
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function GetSuffix(Type As libsodium.Exporting.ExportableType) As String
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
		  Else
		    Return SalsaSuffix
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GetType(EncodedKey As MemoryBlock) As libsodium.Exporting.ExportableType
		  Static Prefixes() As String = Array(EncryptionPrivatePrefix, EncryptionPublicPrefix, SigningPrivatePrefix, SigningPublicPrefix, SalsaSuffix, SharedPrefix)
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
		    End Select
		  Next
		  Return ExportableType.Unknown
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Import(EncodedKey As MemoryBlock, Optional Passwd As libsodium.Password) As MemoryBlock
		  Dim Type As libsodium.Exporting.ExportableType = GetType(EncodedKey)
		  Dim Prefix, Suffix As String
		  Prefix = GetPrefix(Type)
		  Suffix = GetSuffix(Type)
		  
		  Dim metadata As Dictionary = GetMetaData(EncodedKey)
		  EncodedKey = GetKeyData(EncodedKey, Type)
		  If Passwd <> Nil And metadata <> Nil Then
		    Dim n As MemoryBlock = metadata.Value("Nonce")
		    Dim s As MemoryBlock = metadata.Value("Salt")
		    Dim l As ResourceLimits = metadata.Value("Limits")
		    Dim sk As New libsodium.SKI.SecretKey(Passwd, s, l)
		    EncodedKey = libsodium.SKI.DecryptData(EncodedKey, sk, n)
		    If EncodedKey = Nil Then Raise New SodiumException(ERR_IMPORT_PASSWORD)
		  End If
		  
		  Return Trim(EncodedKey)
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

	#tag Constant, Name = MessagePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = MessageSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = NoncePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 NONCE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = NonceSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 NONCE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SalsaPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SalsaSuffix, Type = String, Dynamic = False, Default = \"-----END XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SharedPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 SHARED KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SharedSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 SHARED KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = SigningPublicSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant


	#tag Enum, Name = ExportableType, Flags = &h1
		CryptPrivate
		  CryptPublic
		  SignPrivate
		  SignPublic
		  Secret
		  SharedSecret
		Unknown
	#tag EndEnum


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
