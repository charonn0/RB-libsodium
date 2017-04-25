#tag Class
Protected Class EncryptionKey
Inherits libsodium.PKI.KeyPair
	#tag Method, Flags = &h1000
		Sub Constructor(PasswordData As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' Generates a key pair by deriving it from a salted hash of the password. The operation is
		  ' deterministic, such that calling this method twice with the same Password, Salt, and Limits
		  ' parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Constructor
		  
		  If Salt = Nil Then Salt = PasswordData.RandomSalt(HashAlgorithm)
		  Me.Constructor(PasswordData.DeriveKey(crypto_box_SECRETKEYBYTES, Salt, Limits, HashAlgorithm))
		  mPasswdSalt = Salt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		Sub Constructor(FromSigningKey As libsodium.PKI.SigningKey)
		  ' Converts the SigningKey(Ed25519) into an EncryptionKey(Curve25519), so that the same
		  ' key pair can be used both for authenticated encryption and digital signatures.
		  ' CAUTION: using the same key for both signing and encryption is not recommended.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/advanced/ed25519-curve25519.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Constructor
		  
		  Dim priv As New MemoryBlock(crypto_box_SECRETKEYBYTES)
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  
		  ' try to convert the public key. This might fail, but it's not fatal since
		  ' the public key can be derived from the private key
		  If crypto_sign_ed25519_pk_to_curve25519(pub, FromSigningKey.PublicKey) <> 0 Then
		    pub = Nil
		  End If
		  
		  ' convert the private key. If this fails then the key can't be converted
		  If crypto_sign_ed25519_sk_to_curve25519(priv, FromSigningKey.PrivateKey) <> 0 Then
		    Raise New SodiumException(ERR_CONVERSION_FAILED)
		  End If
		  
		  If pub <> Nil Then 
		    Me.Constructor(priv, pub) ' store the converted keys
		  Else
		    Me.Constructor(priv) ' derive the public key
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock)
		  ' Given a user's private key this method computes their public key using X25519, a 
		  ' state-of-the-art Elliptic Curve Diffie-Hellman (ECDH) function suitable for a wide 
		  ' variety of applications.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/advanced/scalar_multiplication.html
		  ' https://tools.ietf.org/html/rfc7748
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  CheckSize(PrivateKeyData, crypto_scalarmult_BYTES)
		  
		  Dim pub As New MemoryBlock(crypto_scalarmult_BYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then
		    Me.Constructor(PrivateKeyData, pub)
		  Else
		    Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  CheckSize(PrivateKeyData, crypto_box_SECRETKEYBYTES)
		  CheckSize(PublicKeyData, crypto_box_PUBLICKEYBYTES)
		  
		  // Calling the overridden superclass constructor.
		  // Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock) -- From KeyPair
		  Super.Constructor(PrivateKeyData, PublicKeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Derive(PrivateKeyData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' Given a user's private key this method computes their public key using X25519, a
		  ' state-of-the-art Elliptic Curve Diffie-Hellman (ECDH) function suitable for a wide
		  ' variety of applications.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/advanced/scalar_multiplication.html
		  ' https://tools.ietf.org/html/rfc7748
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Derive
		  
		  Return New EncryptionKey(PrivateKeyData)
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(SaveTo As FolderItem, Optional Passwd As libsodium.Password, OverWrite As Boolean = False) As Boolean
		  ' Exports the EncryptionKey in a format that is understood by EncryptionKey.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Export
		  
		  Try
		    Dim bs As BinaryStream = BinaryStream.Create(SaveTo, OverWrite)
		    bs.Write(Me.Export(Passwd))
		    bs.Close
		  Catch Err As IOException
		    Return False
		  End Try
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(Optional Passwd As libsodium.Password) As MemoryBlock
		  ' Exports the EncryptionKey in a format that is understood by EncryptionKey.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Export
		  
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  bs.Write(libsodium.Exporting.Export(Me.PrivateKey, libsodium.Exporting.ExportableType.CryptPrivate, Passwd))
		  bs.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate(Optional SeedData As MemoryBlock) As libsodium.PKI.EncryptionKey
		  ' This method generates an unpredictable EncryptionKey pair, optionally using the specified seed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Generate
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  Dim priv As New MemoryBlock(crypto_box_SECRETKEYBYTES)
		  If SeedData = Nil Then
		    If crypto_box_keypair(pub, priv) = -1 Then Return Nil
		  Else
		    CheckSize(SeedData, crypto_box_SEEDBYTES)
		    If crypto_box_seed_keypair(pub, priv, SeedData) = -1 Then Return Nil
		  End If
		  Return New EncryptionKey(priv, pub)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As FolderItem, Optional Passwd As libsodium.Password) As libsodium.PKI.EncryptionKey
		  ' Import an EncryptionKey that was exported using EncryptionKey.Export(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Import
		  
		  
		  Dim bs As BinaryStream = BinaryStream.Open(ExportedKey)
		  Dim keydata As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Return Import(keydata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As MemoryBlock, Optional Passwd As libsodium.Password) As libsodium.PKI.EncryptionKey
		  ' Import an EncryptionKey that was exported using EncryptionKey.Export
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Import
		  
		  Dim sk As MemoryBlock = libsodium.Exporting.Import(ExportedKey, Passwd)
		  If sk <> Nil Then Return Derive(sk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.PKI.EncryptionKey) As Integer
		  ' This method overloads the comparison operator (=) allowing direct comparisons between 
		  ' instances of EncryptionKey. The comparison operation itself is a constant-time binary 
		  ' comparison of the private key halves of both key pairs; the public halves are not compared.
		  ' 
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Operator_Compare
		  
		  If OtherKey Is Nil Then Return 1
		  Return Super.Operator_Compare(OtherKey)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a nonce in encryption.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.RandomNonce
		  
		  Return RandomBytes(crypto_box_NONCEBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSeed() As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a seed for EncryptionKey.Generate
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.RandomSeed
		  
		  Return RandomBytes(crypto_box_SEEDBYTES)
		End Function
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
