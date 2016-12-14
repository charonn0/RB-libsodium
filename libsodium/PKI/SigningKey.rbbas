#tag Class
Protected Class SigningKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password)
		  ' this method sometimes fails inexplicably...
		  Dim seckey As MemoryBlock = PasswordData.DeriveKey(crypto_sign_SECRETKEYBYTES, libsodium.SKI.RandomSalt, _
		  ResourceLimits.Interactive, libsodium.Password.ALG_ARGON2)
		  Dim pubkey As MemoryBlock = libsodium.PKI.DeriveSigningKey(seckey)
		  // Calling the overridden superclass constructor.
		  Me.Constructor(seckey, pubkey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		Sub Constructor(PrivateKeyData As MemoryBlock)
		  If PrivateKeyData.Size <> crypto_sign_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  Me.Constructor(PrivateKeyData, pub)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  If PrivateKeyData.Size <> crypto_sign_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  If PublicKeyData.Size <> crypto_sign_PUBLICKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  // Calling the overridden superclass constructor.
		  Super.Constructor(PrivateKeyData, PublicKeyData)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.SigningKey
		  If PrivateKeyData.Size <> crypto_sign_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim pub As New MemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  
		  If crypto_sign_ed25519_sk_to_pk(pub, PrivateKeyData) = 0 Then Return New SigningKey(PrivateKeyData, pub)
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveSeed() As MemoryBlock
		  Dim seed As New MemoryBlock(crypto_sign_SEEDBYTES)
		  If crypto_sign_ed25519_sk_to_seed(seed, Me.PrivateKey) = 0 Then Return seed
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.SigningKey
		  Dim pub As New SecureMemoryBlock(crypto_sign_PUBLICKEYBYTES)
		  Dim priv As New SecureMemoryBlock(crypto_sign_SECRETKEYBYTES)
		  If SeedData = Nil Then
		    If crypto_sign_keypair(pub.TruePtr, priv.TruePtr) = -1 Then Return Nil
		  Else
		    If SeedData.Size <> crypto_sign_SEEDBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    If crypto_sign_seed_keypair(pub.TruePtr, priv.TruePtr, SeedData) = -1 Then Return Nil
		  End If
		  Dim ret As New SigningKey(priv, pub)
		  pub.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  priv.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		  
		  Return ret
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.SigningKey) As Integer
		  If OtherKey Is Nil Then Return 1
		  If libsodium.StrComp(Me.PrivateKey, OtherKey.PrivateKey) Then Return 0
		  Return -1
		End Function
	#tag EndMethod


End Class
#tag EndClass
