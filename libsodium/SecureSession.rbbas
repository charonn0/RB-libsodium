#tag Class
Protected Class SecureSession
	#tag Method, Flags = &h0
		Sub Constructor(MyKey As libsodium.PKI.EncryptionKey, TheirKey As libsodium.PKI.ForeignKey)
		  mSecretKey = Nil
		  mEncryptionKey = MyKey
		  mForeignKey = TheirKey
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(SessionKey As libsodium.SKI.SecretKey)
		  mSecretKey = SessionKey
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Decrypt(Message As MemoryBlock) As MemoryBlock
		  If mSecretKey <> Nil Then
		    Dim p As Pair = ImportSKIMessage(Message)
		    Dim m As String = p.Left
		    Dim n As MemoryBlock = p.Right
		    Return libsodium.SKI.DecryptData(m, mSecretKey, n)
		  Else
		    Dim p As Pair = ImportPKIMessage(Message)
		    Dim m As String = p.Left
		    Dim n As MemoryBlock = p.Right
		    Return libsodium.PKI.DecryptData(m, mForeignKey, mEncryptionKey, n)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Encrypt(Message As MemoryBlock) As MemoryBlock
		  Dim msg As MemoryBlock
		  Dim n As MemoryBlock
		  If mSecretKey <> Nil Then
		    n = mSecretKey.RandomNonce
		    msg = ExportSKIMessage(libsodium.SKI.EncryptData(Message, mSecretKey, n), n)
		  Else
		    n = mEncryptionKey.RandomNonce
		    msg = ExportPKIMessage(libsodium.PKI.EncryptData(Message, mForeignKey, mEncryptionKey, n), n)
		  End If
		  Return msg
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ExportPKIMessage(ExportedMessage As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  output.Write(ExportEncryptionMessagePrefix + EndOfLine.Windows)
		  output.Write("#Nonce=" + EncodeBase64(Nonce) + EndOfLine.Windows)
		  output.Write(EndOfLine.Windows)
		  output.Write(EncodeBase64(ExportedMessage) + EndOfLine.Windows)
		  output.Write(ExportEncryptionMessageSuffix + EndOfLine.Windows)
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ExportSKIMessage(ExportedMessage As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim output As New BinaryStream(data)
		  output.Write(ExportSecretMessagePrefix + EndOfLine.Windows)
		  output.Write("#Nonce=" + EncodeBase64(Nonce) + EndOfLine.Windows)
		  output.Write(EndOfLine.Windows)
		  output.Write(EncodeBase64(ExportedMessage) + EndOfLine.Windows)
		  output.Write(ExportSecretMessageSuffix + EndOfLine.Windows)
		  output.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ImportPKIMessage(ExportedMessage As MemoryBlock) As Pair
		  ExportedMessage = ReplaceLineEndings(ExportedMessage, EndOfLine.Windows)
		  Dim lines() As String = SplitB(ExportedMessage, EndOfLine.Windows)
		  Dim i As Integer
		  
		  Do Until Ubound(lines) <= i Or lines(i) = ExportEncryptionMessagePrefix
		    i = i + 1
		  Loop
		  If i = UBound(lines) Then Return Nil
		  Dim msg As New MemoryBlock(0)
		  Dim output As New BinaryStream(msg)
		  Dim Nonce As MemoryBlock
		  For i = i + 1 To UBound(lines)
		    Dim s As String = lines(i)
		    Select Case True
		    Case Left(s, 7) = "#Nonce="
		      Nonce = DecodeBase64(Right(s, s.Len - 7))
		    Case Left(s, 1) = "#", s.Trim = "" ' comment/blank line
		      Continue
		    Case s = ExportEncryptionMessageSuffix
		      Exit For
		    Else
		      output.Write(s + EndOfLine.Windows)
		    End Select
		  Next
		  output.Close
		  Return DecodeBase64(msg.Trim):Nonce
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ImportSKIMessage(ExportedMessage As MemoryBlock) As Pair
		  ExportedMessage = ReplaceLineEndings(ExportedMessage, EndOfLine.Windows)
		  Dim lines() As String = SplitB(ExportedMessage, EndOfLine.Windows)
		  Dim i As Integer
		  
		  Do Until Ubound(lines) <= i Or lines(i) = ExportSecretMessagePrefix
		    i = i + 1
		  Loop
		  If i = UBound(lines) Then Return Nil
		  Dim msg As New MemoryBlock(0)
		  Dim output As New BinaryStream(msg)
		  Dim Nonce As MemoryBlock
		  For i = i + 1 To UBound(lines)
		    Dim s As String = lines(i)
		    Select Case True
		    Case Left(s, 7) = "#Nonce="
		      Nonce = DecodeBase64(Right(s, s.Len - 7))
		    Case Left(s, 1) = "#", s.Trim = "" ' comment/blank line
		      Continue
		    Case s = ExportSecretMessageSuffix
		      Exit For
		    Else
		      output.Write(s + EndOfLine.Windows)
		    End Select
		  Next
		  output.Close
		  Return DecodeBase64(msg.Trim):Nonce
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mEncryptionKey As libsodium.PKI.EncryptionKey
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mForeignKey As libsodium.PKI.ForeignKey
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mSecretKey As libsodium.SKI.SecretKey
	#tag EndProperty


	#tag Constant, Name = ExportEncryptionMessagePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionMessageSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 MESSAGE-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSecretMessagePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSecretMessageSuffix, Type = String, Dynamic = False, Default = \"-----END XSALSA20 KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSignaturePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 SIGNATURE BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSignatureSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 SIGNATURE BLOCK-----", Scope = Private
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
