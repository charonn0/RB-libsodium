#tag Class
Protected Class Exportable
	#tag Method, Flags = &h21
		Private Sub Constructor(Optional Passwd As libsodium.Password)
		  mPasswd = Passwd
		  If mPasswd <> Nil Then
		    mPasswdSalt = mPasswd.RandomSalt
		    mNonce = libsodium.SKI.SecretKey.RandomNonce
		  End If
		  mMetaData = New Dictionary
		  mPasswdLimits = ResourceLimits.Interactive
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(ExportedKey As libsodium.PKI.EncryptionKey, Optional Passwd As libsodium.Password)
		  mData = ExportedKey.PrivateKey
		  mNonce = ExportedKey.RandomNonce
		  mPrefix = ExportEncryptionPrivatePrefix
		  mSuffix = ExportEncryptionPrivateSuffix
		  Me.Constructor(Passwd)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(ExportedKey As libsodium.PKI.SigningKey, Optional Passwd As libsodium.Password)
		  mData = ExportedKey.PrivateKey
		  mPrefix = ExportSigningPrivatePrefix
		  mSuffix = ExportSigningPrivateSuffix
		  Me.Constructor(Passwd)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor1(ExportedKey As MemoryBlock, Type As ExportableType, Prefix As String, Suffix As String, Optional Passwd As libsodium.Password)
		  ExportedKey = ReplaceLineEndings(ExportedKey, EndOfLine.Windows)
		  mType = Type
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  Dim i As Integer
		  Do Until Ubound(lines) <= i Or lines(i) = Prefix
		    i = i + 1
		  Loop
		  If i = UBound(lines) Then Raise New UnsupportedFormatException
		  
		  mData = New MemoryBlock(0)
		  mMetaData = New Dictionary
		  Dim output As New BinaryStream(mData)
		  
		  For i = i + 1 To UBound(lines)
		    Dim s As String = lines(i)
		    Select Case True
		    Case Left(s, 6) = "#Salt="
		      mPasswdSalt = DecodeBase64(Right(s, s.Len - 6))
		    Case Left(s, 7) = "#Nonce="
		      mNonce = DecodeBase64(Right(s, s.Len - 7))
		    Case Left(s, 8) = "#Limits="
		      Select Case Right(s, s.Len - 8)
		      Case "Interactive"
		        mPasswdLimits = ResourceLimits.Interactive
		      Case "Moderate"
		        mPasswdLimits = ResourceLimits.Moderate
		      Case "Sensitive"
		        mPasswdLimits = ResourceLimits.Sensitive
		      Else
		        Raise New UnsupportedFormatException
		      End Select
		    Case Left(s, 1) = "#", s.Trim = "" ' comment/blank line
		      If Left(s, 1) = "#" And s.Len > 1 Then
		        Dim n As String = NthField(s, "=", 1)
		        Dim v As String = Right(s, s.Len - n.Len)
		        n = Right(n, n.Len - 1)
		        mMetaData.Value(n) = v
		      End If
		      Continue
		    Case s = Suffix
		      Exit For
		    Else
		      output.Write(s + EndOfLine.Windows)
		    End Select
		  Next
		  output.Close
		  mData = DecodeBase64(mData.Trim)
		  If Passwd <> Nil Then
		    Dim sk As New libsodium.SKI.SecretKey(Passwd, mPasswdSalt, mPasswdLimits)
		    mData = libsodium.SKI.DecryptData(mData, sk, mNonce)
		  End If
		  
		  If mData <> Nil Then mData = Trim(mData) Else Raise New UnsupportedFormatException
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export() As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  Dim ExportedKey As MemoryBlock
		  output.Write(mPrefix + EndOfLine.Windows)
		  
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
		  output.Write(mSuffix + EndOfLine.Windows)
		  
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function ParseKey(ExportedKey As MemoryBlock, Type As ExportableType, Prefix As String, Suffix As String, Optional Passwd As libsodium.Password) As libsodium.Exportable
		  Dim ret As New Exportable
		  ExportedKey = ReplaceLineEndings(ExportedKey, EndOfLine.Windows)
		  ret.mType = Type
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  Dim i As Integer
		  Do Until Ubound(lines) <= i Or lines(i) = Prefix
		    i = i + 1
		  Loop
		  If i = UBound(lines) Then Raise New UnsupportedFormatException
		  
		  ret.mData = New MemoryBlock(0)
		  ret.mMetaData = New Dictionary
		  Dim output As New BinaryStream(ret.mData)
		  
		  For i = i + 1 To UBound(lines)
		    Dim s As String = lines(i)
		    Select Case True
		    Case Left(s, 6) = "#Salt="
		      ret.mPasswdSalt = DecodeBase64(Right(s, s.Len - 6))
		    Case Left(s, 7) = "#Nonce="
		      ret.mNonce = DecodeBase64(Right(s, s.Len - 7))
		    Case Left(s, 8) = "#Limits="
		      Select Case Right(s, s.Len - 8)
		      Case "Interactive"
		        ret.mPasswdLimits = ResourceLimits.Interactive
		      Case "Moderate"
		        ret.mPasswdLimits = ResourceLimits.Moderate
		      Case "Sensitive"
		        ret.mPasswdLimits = ResourceLimits.Sensitive
		      Else
		        Raise New UnsupportedFormatException
		      End Select
		    Case Left(s, 1) = "#", s.Trim = "" ' comment/blank line
		      If Left(s, 1) = "#" And s.Len > 1 Then
		        Dim n As String = NthField(s, "=", 1)
		        Dim v As String = Right(s, s.Len - n.Len)
		        n = Right(n, n.Len - 1)
		        ret.mMetaData.Value(n) = v
		      End If
		      Continue
		    Case s = Suffix
		      Exit For
		    Else
		      output.Write(s + EndOfLine.Windows)
		    End Select
		  Next
		  output.Close
		  ret.mData = DecodeBase64(ret.mData.Trim)
		  If Passwd <> Nil Then
		    Dim sk As New libsodium.SKI.SecretKey(Passwd, ret.mPasswdSalt, ret.mPasswdLimits)
		    ret.mData = libsodium.SKI.DecryptData(ret.mData, sk, ret.mNonce)
		  End If
		  
		  If ret.mData <> Nil Then ret.mData = Trim(ret.mData) Else Raise New UnsupportedFormatException
		  Return ret
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
		Private mPrefix As String
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mSuffix As String
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
