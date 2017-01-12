#tag Class
Protected Class KeyPair
Implements libsodium.Secureable
	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  mPrivate = New libsodium.SKI.KeyContainer(PrivateKeyData)
		  mPublic = PublicKeyData
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  Secureable(mPrivate).Lock
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.KeyPair) As Integer
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
		Function DeriveSubkey(SubkeySize As UInt32, Salt As MemoryBlock, AppID As MemoryBlock) As MemoryBlock
		  CheckSize(Salt, crypto_generichash_blake2b_SALTBYTES)
		  Dim subkey As New MemoryBlock(SubkeySize)
		  CheckSize(subkey, 128 / 8, 512 / 8)
		  Dim err As Int32
		  If AppID <> Nil Then
		    CheckSize(AppID, crypto_generichash_blake2b_PERSONALBYTES)
		    Dim v As MemoryBlock = Me.Value
		    err = crypto_generichash_blake2b_salt_personal(Subkey, Subkey.Size, Nil, 0, v, v.Size, Salt, AppID)
		  Else
		    Dim v As MemoryBlock = Me.Value
		    err = crypto_generichash_blake2b_salt_personal(Subkey, Subkey.Size, Nil, 0, v, v.Size, Salt, Nil)
		  End If
		  If err <> 1 Then Return Nil
		  Return subkey
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
		 Shared Function RandomSalt() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a salt for use with an DeriveSubKey
		  
		  Return RandomBytes(crypto_pwhash_SALTBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  Secureable(mPrivate).Unlock
		End Sub
	#tag EndMethod


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
