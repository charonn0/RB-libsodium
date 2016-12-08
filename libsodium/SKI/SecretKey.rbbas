#tag Class
Protected Class SecretKey
Inherits libsodium.KeyPair
	#tag Method, Flags = &h1021
		Private Sub Constructor(PrivateKeyData As libsodium.SecureMemoryBlock, PublicKeyData As libsodium.SecureMemoryBlock)
		  If PKSessionNonce = Nil Then PKSessionNonce = libsodium.PKI.RandomNonce
		  Dim key As MemoryBlock = libsodium.PKI.RandomKey
		  PKSessionKey = libsodium.PKI.DeriveSharedKey(libsodium.PKI.DerivePublicKey(key), key)
		  PrivateKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  PublicKeyData.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  mPrivate = libsodium.PKI.EncryptData(PrivateKeyData, PKSessionKey, PKSessionNonce)
		  mPublic = libsodium.PKI.EncryptData(PublicKeyData, PKSessionKey, PKSessionNonce)
		  mPrivate.AllowSwap = False
		  mPublic.AllowSwap = False
		  mPrivate.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  mPublic.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		Sub Constructor(SecretKeyData As MemoryBlock)
		  Me.Constructor(SecretKeyData, libsodium.RandomBytes(crypto_secretbox_KEYBYTES))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate() As libsodium.SKI.SecretKey
		  Return libsodium.SKI.RandomKey
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function PrivateKey() As MemoryBlock
		  If PKSessionKey <> Nil Then 
		    Return libsodium.PKI.DecryptData(Super.PrivateKey, PKSessionKey, PKSessionNonce) 
		  Else 
		    Return Super.PrivateKey
		  End If
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function PublicKey() As MemoryBlock
		  If PKSessionKey <> Nil Then
		    Return libsodium.PKI.DecryptData(Super.PublicKey, PKSessionKey, PKSessionNonce)
		  Else
		    Return Super.PublicKey
		  End If
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Return Me.PrivateKey
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private PKSessionKey As SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared PKSessionNonce As MemoryBlock
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
