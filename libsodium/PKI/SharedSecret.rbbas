#tag Class
Protected Class SharedSecret
Implements libsodium.Secureable
	#tag Method, Flags = &h1000
		Sub Constructor(RecipientPublicKey As MemoryBlock, SenderPrivateKey As libsodium.PKI.EncryptionKey)
		  ' Calculates the shared secret from the RecipientPublicKey and SenderPrivateKey. 
		  ' This allows the key derivation calculation to be performed once rather than on 
		  ' Encrypt/Decrypt
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(RecipientPublicKey, crypto_box_PUBLICKEYBYTES)
		  
		  Dim buffer As New MemoryBlock(crypto_box_BEFORENMBYTES)
		  If crypto_box_beforenm(buffer, RecipientPublicKey, SenderPrivateKey.PrivateKey) <> 0 Then 
		    Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  End If
		  mKeyData = New libsodium.SKI.KeyContainter(buffer)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function DeriveSharedSecret(RecipientPublicKey As MemoryBlock, SenderPrivateKey As libsodium.PKI.EncryptionKey) As MemoryBlock
		  ' Computes a shared secret given a SenderPrivateKey and RecipientPublicKey.
		  ' The return value represents the X coordinate of a point on the curve. As
		  ' a result, the number of possible keys is limited to the group size (≈2^252),
		  ' and the key distribution is not uniform. For this reason, instead of directly
		  ' using the return value as a shared key, it is recommended to use:
		  '
		  '  GenericHash(return value + RecipientPublicKey + Sender's PUBLIC KEY)
		  '
		  ' Or just call the Constructor
		  
		  CheckSize(RecipientPublicKey, crypto_scalarmult_BYTES)
		  
		  Dim buffer As New MemoryBlock(crypto_scalarmult_BYTES)
		  If crypto_scalarmult(buffer, SenderPrivateKey.PrivateKey, RecipientPublicKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  If mKeyData <> Nil Then Secureable(mKeyData).Lock
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  If mKeyData <> Nil Then Secureable(mKeyData).Unlock
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As MemoryBlock
		  Return mKeyData.Value
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mKeyData As libsodium.SKI.KeyContainter
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared mSessionKey As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared SessionNonce As MemoryBlock
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
