#tag Class
Private Class Exportable
	#tag Method, Flags = &h0
		Sub Constructor(ExportedKey As MemoryBlock, Type As DataType, Prefix As String, Suffix As String, Optional Passwd As libsodium.Password)
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
		Private mType As DataType
	#tag EndProperty


	#tag Enum, Name = DataType, Type = Integer, Flags = &h0
		EncryptionSecretKey
		  EncryptionPublicKey
		  SigningSecretKey
		  SigningPublicKey
		  SecretKey
		  PKINonce
		  SKINonce
		  ArgonSalt
		  ScryptSalt
		  PKIMessage
		  SKIMessage
		MAC
	#tag EndEnum


End Class
#tag EndClass
