#tag Class
Protected Class Exportable
	#tag Method, Flags = &h0
		Sub Constructor(ExportedKey As libsodium.PKI.EncryptionKey, Optional Passwd As libsodium.Password)
		  If Passwd <> Nil Then
		    Me.Constructor(ExportedKey.PrivateKey, libsodium.SKI.SecretKey.RandomNonce, ResourceLimits.Interactive, Passwd.RandomSalt, ExportableType.CryptPrivate, Passwd)
		  Else
		    Me.Constructor(ExportedKey.PublicKey, Nil, ResourceLimits.Interactive, Nil, ExportableType.CryptPublic, Nil)
		  End If
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(ExportedKey As libsodium.PKI.SigningKey, Optional Passwd As libsodium.Password)
		  If Passwd <> Nil Then
		    Me.Constructor(ExportedKey.PrivateKey, libsodium.SKI.SecretKey.RandomNonce, ResourceLimits.Interactive, Passwd.RandomSalt, ExportableType.SignPrivate, Passwd)
		  Else
		    Me.Constructor(ExportedKey.PublicKey, Nil, ResourceLimits.Interactive, Nil, ExportableType.SignPublic, Nil)
		  End If
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Constructor(RawKey As MemoryBlock, Nonce As MemoryBlock, Limits As libsodium.ResourceLimits, Salt As MemoryBlock, Type As libsodium.ExportableType, Passwd As libsodium.Password, Meta As Dictionary = Nil)
		  If Meta = Nil Then mMetaData = New Dictionary Else mMetaData = Meta
		  mData = RawKey
		  mNonce = Nonce
		  mPasswdLimits = Limits
		  mPasswdSalt = Salt
		  mType = Type
		  mPasswd = Passwd
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export() As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  Dim ExportedKey As MemoryBlock
		  output.Write(GetPrefix(mType) + EndOfLine.Windows)
		  
		  If mPasswd <> Nil Then
		    If mPasswdSalt = Nil Then mPasswdSalt = mPasswd.RandomSalt
		    Dim key As libsodium.SKI.SecretKey
		    If mNonce = Nil Then mNonce = key.RandomNonce Else mNonce = IncrementNonce(mNonce)
		    key = New libsodium.SKI.SecretKey(mPasswd, mPasswdSalt, mPasswdLimits)
		    ExportedKey = libsodium.SKI.EncryptData(mData, key, mNonce)
		    output.Write("#Salt=" + EncodeBase64(mPasswdSalt) + EndOfLine.Windows)
		    output.Write("#Nonce=" + EncodeBase64(mNonce) + EndOfLine.Windows)
		    Select Case mPasswdLimits
		    Case ResourceLimits.Interactive
		      output.Write("#Limits=Interactive" + EndOfLine.Windows)
		    Case ResourceLimits.Moderate
		      output.Write("#Limits=Moderate" + EndOfLine.Windows)
		    Case ResourceLimits.Sensitive
		      output.Write("#Limits=Sensitive" + EndOfLine.Windows)
		    End Select
		  Else
		    ExportedKey = mData
		  End If
		  For Each Key As String In mMetaData.Keys
		    output.Write("#" + Key + "=" + mMetaData.Value(Key) + EndOfLine.Windows)
		  Next
		  output.Write(EndOfLine.Windows)
		  output.Write(EncodeBase64(ExportedKey) + EndOfLine.Windows)
		  output.Write(GetSuffix(mType) + EndOfLine.Windows)
		  
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(SaveTo As FolderItem, OverWrite As Boolean = False) As Boolean
		  ' Exports the key in a format that is understood by Exportable.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.Exportable.Export
		  
		  Try
		    Dim bs As BinaryStream = BinaryStream.Create(SaveTo, OverWrite)
		    bs.Write(Me.Export)
		    bs.Close
		  Catch Err As IOException
		    Return False
		  End Try
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function GetPrefix(Type As libsodium.ExportableType) As String
		  Select Case Type
		  Case ExportableType.CryptPrivate
		    Return ExportEncryptionPrivatePrefix
		  Case ExportableType.CryptPublic
		    Return ExportEncryptionPublicPrefix
		  Case ExportableType.SignPrivate
		    Return ExportSigningPrivatePrefix
		  Case ExportableType.SignPublic
		    Return ExportSigningPublicPrefix
		  Else
		    Return ExportPrefix
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function GetRawKeyData(ByRef EncodedKey As MemoryBlock, Prefix As String, Suffix As String, ByRef Salt As MemoryBlock, ByRef Nonce As MemoryBlock, ByRef Limits As libsodium.ResourceLimits, ByRef MetaData As Dictionary) As Boolean
		  EncodedKey = ReplaceLineEndings(EncodedKey, EndOfLine.Windows)
		  Dim lines() As String = SplitB(EncodedKey, EndOfLine.Windows)
		  Dim i As Integer
		  Do Until Ubound(lines) <= i Or lines(i) = Prefix
		    i = i + 1
		  Loop
		  If i = UBound(lines) Then Return False
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  MetaData = New Dictionary
		  For i = i + 1 To UBound(lines)
		    Dim s As String = lines(i)
		    Select Case True
		    Case Left(s, 6) = "#Salt="
		      Salt = DecodeBase64(Right(s, s.Len - 6))
		    Case Left(s, 7) = "#Nonce="
		      Nonce = DecodeBase64(Right(s, s.Len - 7))
		    Case Left(s, 8) = "#Limits="
		      Select Case Right(s, s.Len - 8)
		      Case "Interactive"
		        Limits = ResourceLimits.Interactive
		      Case "Moderate"
		        Limits = ResourceLimits.Moderate
		      Case "Sensitive"
		        Limits = ResourceLimits.Sensitive
		      Else
		        Return False
		      End Select
		    Case Left(s, 1) = "#", s.Trim = "" ' comment/blank line
		      If Left(s, 1) = "#" And s.Len > 1 Then
		        Dim n As String = NthField(s, "=", 1)
		        Dim v As String = Right(s, s.Len - n.Len)
		        n = Right(n, n.Len - 1)
		        MetaData.Value(n) = v
		      End If
		      Continue
		    Case s = Suffix
		      Exit For
		    Else
		      output.Write(s + EndOfLine.Windows)
		    End Select
		  Next
		  output.Close
		  EncodedKey = DecodeBase64(data.Trim)
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Function GetSuffix(Type As libsodium.ExportableType) As String
		  Select Case Type
		  Case ExportableType.CryptPrivate
		    Return ExportEncryptionPrivateSuffix
		  Case ExportableType.CryptPublic
		    Return ExportEncryptionPublicSuffix
		  Case ExportableType.SignPrivate
		    Return ExportSigningPrivateSuffix
		  Case ExportableType.SignPublic
		    Return ExportSigningPublicSuffix
		  Else
		    Return ExportSuffix
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function GetType(EncodedKey As MemoryBlock) As libsodium.ExportableType
		  Static Prefixes() As String = Array(ExportEncryptionPrivatePrefix, ExportEncryptionPublicPrefix, ExportSigningPrivatePrefix, ExportSigningPublicPrefix, ExportSuffix)
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
		    End Select
		  Next
		  Return ExportableType.Unknown
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As FolderItem, Optional Passwd As libsodium.Password) As libsodium.Exportable
		  ' Import an key that was exported using Exportable.Export(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.Exportable.Import
		  
		  
		  Dim bs As BinaryStream = BinaryStream.Open(ExportedKey)
		  Dim keydata As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Return Import(keydata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As MemoryBlock, Optional Passwd As libsodium.Password) As libsodium.Exportable
		  Dim Type As libsodium.ExportableType = GetType(ExportedKey)
		  Dim Prefix, Suffix As String
		  Prefix = GetPrefix(Type)
		  Suffix = GetSuffix(Type)
		  Dim salt, nonce As MemoryBlock
		  Dim metadata As Dictionary
		  Dim limits As libsodium.ResourceLimits
		  
		  If Not GetRawKeyData(ExportedKey, Prefix, Suffix, salt, nonce, limits, metadata) Then Raise New UnsupportedFormatException
		  If ExportedKey = Nil Then Raise New UnsupportedFormatException
		  
		  If Passwd <> Nil Then
		    Dim sk As New libsodium.SKI.SecretKey(Passwd, salt, limits)
		    ExportedKey = libsodium.SKI.DecryptData(ExportedKey, sk, nonce)
		  End If
		  
		  If ExportedKey <> Nil Then ExportedKey = Trim(ExportedKey) Else Raise New UnsupportedFormatException
		  Return New Exportable(ExportedKey, nonce, limits, salt, Type, Passwd, metadata)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Type() As libsodium.ExportableType
		  Return mType
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Return mData
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mData As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mMetaData As Dictionary
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mNonce As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mPasswd As libsodium.Password
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mPasswdLimits As libsodium.ResourceLimits
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mPasswdSalt As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mType As ExportableType
	#tag EndProperty


	#tag Constant, Name = ExportEncryptionPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPublicSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportMessagePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportMessageSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportNoncePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 NONCE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportNonceSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 NONCE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPublicSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSuffix, Type = String, Dynamic = False, Default = \"-----END XSALSA20 KEY BLOCK-----", Scope = Private
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
End Class
#tag EndClass
