#tag Class
Protected Class ForeignKey
	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.EncryptionKey)
		  Me.Constructor(FromKey.PublicKey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(FromKey As libsodium.PKI.SigningKey)
		  Me.Constructor(FromKey.PublicKey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As MemoryBlock)
		  CheckSize(KeyData, crypto_box_PUBLICKEYBYTES)
		  mKeyData = KeyData
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
		Function Value() As MemoryBlock
		  Return mKeyData
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mKeyData As MemoryBlock
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
End Class
#tag EndClass
