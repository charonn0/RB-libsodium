#tag Class
Protected Class SecretKey
Inherits libsodium.KeyPair
	#tag Method, Flags = &h1021
		Private Sub Constructor(PrivateKeyData As libsodium.SecureMemoryBlock, PublicKeyData As libsodium.SecureMemoryBlock)
		  // Calling the overridden superclass constructor.
		  Super.Constructor(PrivateKeyData, PublicKeyData)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(SecretKeyData As MemoryBlock)
		  // Calling the overridden superclass constructor.
		  Super.Constructor(SecretKeyData, "")
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate() As libsodium.SKI.SecretKey
		  Return New SecretKey(libsodium.SKI.RandomKey)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromMemoryBlock As MemoryBlock)
		  Me.Constructor(FromMemoryBlock)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function PrivateKey() As MemoryBlock
		  Return Super.PrivateKey
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function PublicKey() As MemoryBlock
		  Return Super.PublicKey
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Return Super.PrivateKey
		End Function
	#tag EndMethod


End Class
#tag EndClass
