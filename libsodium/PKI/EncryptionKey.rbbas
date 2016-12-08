#tag Class
Protected Class EncryptionKey
Inherits libsodium.KeyPair
	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  If PrivateKeyData.Size <> crypto_box_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim priv As New SecureMemoryBlock(crypto_box_SECRETKEYBYTES)
		  Dim pub As New SecureMemoryBlock(crypto_box_PUBLICKEYBYTES)
		  priv.StringValue(0, priv.Size) = PrivateKeyData
		  Dim err As Int32 = crypto_scalarmult_base(pub.TruePtr, priv.TruePtr)
		  
		  If err = 0 Then
		    pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    priv.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		    Return New EncryptionKey(priv, pub)
		  Else
		    Raise New SodiumException(err)
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


End Class
#tag EndClass
