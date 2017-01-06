#tag Class
Protected Class ForeignKey
	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.EncryptionKey)
		  Me.Constructor(FromKey.PublicKey)
		  mType = KeyType.Encryption
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.SigningKey)
		  Me.Constructor(FromKey.PublicKey)
		  mType = KeyType.Signature
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As MemoryBlock)
		  Select Case True
		  Case InStrB(KeyData, "-----BEGIN ED25519 PUBLIC KEY BLOCK-----") > 0
		    mKeyData = ImportSigningKey(KeyData)
		    mType = KeyType.Signature
		    CheckSize(mKeyData, crypto_sign_PUBLICKEYBYTES)
		  Case InStrB(KeyData, "-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----") > 0
		    mKeyData = ImportEncryptionKey(KeyData)
		    mType = KeyType.Encryption
		    CheckSize(mKeyData, crypto_box_PUBLICKEYBYTES)
		  Case InStrB(KeyData, "-----BEGIN PUBLIC KEY BLOCK-----") > 0
		    mKeyData = ImportGenericKey(KeyData)
		    mType = KeyType.Generic
		  Else
		    mKeyData = KeyData
		    mType = KeyType.Unknown
		  End Select
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ConvertSigningKey() As libsodium.PKI.ForeignKey
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  If crypto_sign_ed25519_pk_to_curve25519(pub, Me.Value) <> 0 Then
		    Dim err As New SodiumException(ERR_CONVERSION_FAILED)
		    err.Message = "This public key cannot be converted."
		    Raise err
		  End If
		  Return New ForeignKey(pub)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export() As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  
		  Select Case mType
		  Case KeyType.Signature
		    bs.Write("-----BEGIN ED25519 PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  Case KeyType.Encryption
		    bs.Write("-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  Else
		    bs.Write("-----BEGIN PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  End Select
		  bs.Write(EndOfLine.Windows)
		  bs.Write(EncodeBase64(Me.Value) + EndOfLine.Windows)
		  
		  Select Case mType
		  Case KeyType.Signature
		    bs.Write("-----END ED25519 PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  Case KeyType.Encryption
		    bs.Write("-----END CURVE25519 PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  Else
		    bs.Write("-----END PUBLIC KEY BLOCK-----" + EndOfLine.Windows)
		  End Select
		  
		  bs.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ImportEncryptionKey(ExportedKey As MemoryBlock) As MemoryBlock
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  Dim pk As New MemoryBlock(0)
		  Dim bs As New BinaryStream(pk)
		  Dim i As Integer
		  For i = 1 To UBound(lines)
		    If lines(i) <> "-----END CURVE25519 PUBLIC KEY BLOCK-----" Then
		      bs.Write(lines(i) + EndOfLine.Windows)
		    Else
		      Exit For
		    End If
		  Next
		  bs.Close
		  Return DecodeBase64(pk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ImportGenericKey(ExportedKey As MemoryBlock) As MemoryBlock
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  Dim kd As New MemoryBlock(0)
		  Dim bs As New BinaryStream(kd)
		  Dim i As Integer
		  For i = 1 To UBound(lines)
		    If lines(i) <> "-----END PUBLIC KEY BLOCK-----" Then
		      bs.Write(lines(i) + EndOfLine.Windows)
		    Else
		      Exit For
		    End If
		  Next
		  bs.Close
		  Return DecodeBase64(kd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Shared Function ImportSigningKey(ExportedKey As MemoryBlock) As MemoryBlock
		  Dim lines() As String = SplitB(ExportedKey, EndOfLine.Windows)
		  Dim pk As New MemoryBlock(0)
		  Dim bs As New BinaryStream(pk)
		  Dim i As Integer
		  For i = 1 To UBound(lines)
		    If lines(i) <> "-----END ED25519 PUBLIC KEY BLOCK-----" Then
		      bs.Write(lines(i) + EndOfLine.Windows)
		    Else
		      Exit For
		    End If
		  Next
		  bs.Close
		  Return DecodeBase64(pk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Length() As Int32
		  Return mKeyData.Size
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.ForeignKey) As Int32
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.Value, OtherKey.Value) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As String) As Int32
		  ' Performs a constant-time binary comparison to the OtherKey
		  If libsodium.StrComp(Me.Value, OtherKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromString As String)
		  Me.Constructor(FromString)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Type() As libsodium.PKI.ForeignKey.KeyType
		  Return mType
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Return mKeyData
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mKeyData As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mType As libsodium.PKI.ForeignKey.KeyType
	#tag EndProperty


	#tag Enum, Name = KeyType, Type = Integer, Flags = &h0
		Encryption
		  Signature
		  Generic
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
End Class
#tag EndClass
