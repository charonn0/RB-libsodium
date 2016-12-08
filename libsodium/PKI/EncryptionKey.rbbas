#tag Class
Protected Class EncryptionKey
Inherits libsodium.KeyPair
	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  If PrivateKeyData.Size <> crypto_box_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim pub As SecureMemoryBlock = DerivePublicKey(PrivateKeyData)
		  
		  If pub <> Nil Then
		    pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    Return New EncryptionKey(PrivateKeyData, pub)
		  End If
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  Dim pub As New SecureMemoryBlock(crypto_box_PUBLICKEYBYTES)
		  Dim priv As New SecureMemoryBlock(crypto_box_SECRETKEYBYTES)
		  If SeedData = Nil Then
		    If crypto_box_keypair(pub.TruePtr, priv.TruePtr) = -1 Then Return Nil
		  Else
		    If SeedData.Size <> crypto_box_SEEDBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    If crypto_box_seed_keypair(pub.TruePtr, priv.TruePtr, SeedData) = -1 Then Return Nil
		  End If
		  Dim ret As New EncryptionKey(priv, pub)
		  pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  priv.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  
		  Return ret
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromSigningKey As libsodium.PKI.SigningKey)
		  Dim priv As New SecureMemoryBlock(crypto_box_SECRETKEYBYTES)
		  priv.StringValue(0, priv.Size) = FromSigningKey.PrivateKey
		  Dim pub As New SecureMemoryBlock(crypto_box_PUBLICKEYBYTES)
		  
		  If crypto_sign_ed25519_pk_to_curve25519(pub.TruePtr, priv.TruePtr) = 0 Then
		    pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    priv.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    Super.Constructor(priv, pub)
		  End If
		  
		End Sub
	#tag EndMethod


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
