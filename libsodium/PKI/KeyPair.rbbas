#tag Class
Protected Class KeyPair
	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  mPrivate = New libsodium.SKI.KeyContainer(PrivateKeyData)
		  If PublicKeyData.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED) ' can't pass a MemoryBlock of unknown size
		  mPublic = PublicKeyData
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.KeyPair) As Int32
		  ' This method overloads the comparison operator (=) allowing direct comparisons between
		  ' instances of KeyPair. The comparison operation itself is a constant-time binary
		  ' comparison of the private key halves of both key pairs; the public halves are not compared.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.KeyPair.Operator_Compare
		  
		  If OtherKey Is Nil Then Return 1
		  Return mPrivate.Operator_Compare(OtherKey.PrivateKey)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PrivateKey() As MemoryBlock
		  Return mPrivate.Value()
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PublicKey() As MemoryBlock
		  Return mPublic
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Salt() As MemoryBlock
		  ' If the KeyPair was derived from a Password then this method will return the salt, otherwise it returns Nil.
		  
		  Return mPasswdSalt
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mPasswdSalt As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPrivate As libsodium.SKI.KeyContainer
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPublic As MemoryBlock
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
