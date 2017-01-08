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
		Sub Constructor(KeyData As MemoryBlock, Optional Passwd As libsodium.Password)
		  Select Case True
		  Case InStrB(KeyData, libsodium.PKI.SigningKey.PublicPrefix) > 0
		    mKeyData = ExtractKey(KeyData, libsodium.PKI.SigningKey.PublicPrefix, libsodium.PKI.SigningKey.PublicSuffix, Passwd)
		    mType = KeyType.Signature
		    CheckSize(mKeyData, crypto_sign_PUBLICKEYBYTES)
		  Case InStrB(KeyData, libsodium.PKI.EncryptionKey.PublicPrefix) > 0
		    mKeyData = ExtractKey(KeyData, libsodium.PKI.EncryptionKey.PublicPrefix, libsodium.PKI.EncryptionKey.PublicSuffix, Passwd)
		    mType = KeyType.Encryption
		    CheckSize(mKeyData, crypto_box_PUBLICKEYBYTES)
		  Case InStrB(KeyData, ExportPrefix) > 0
		    mKeyData = ExtractKey(KeyData, ExportPrefix, ExportSuffix, Passwd)
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
		Function Export(Optional Passwd As libsodium.Password) As MemoryBlock
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  Dim prefix, suffix As String
		  Select Case mType
		  Case KeyType.Signature
		    prefix = libsodium.PKI.SigningKey.PublicPrefix
		    suffix = libsodium.PKI.SigningKey.PublicSuffix
		  Case KeyType.Encryption
		    prefix = libsodium.PKI.EncryptionKey.PublicPrefix
		    suffix = libsodium.PKI.EncryptionKey.PublicSuffix
		  Else
		    prefix = ExportPrefix
		    suffix = ExportSuffix
		  End Select
		  bs.Write(PackKey(Me.Value, prefix, suffix, Passwd))
		  bs.Close
		  Return data
		  
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


	#tag Constant, Name = ExportPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN PUBLIC KEY BLOCK-----", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ExportSuffix, Type = String, Dynamic = False, Default = \"-----END PUBLIC KEY BLOCK-----", Scope = Protected
	#tag EndConstant


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
