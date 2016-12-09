#tag Module
Protected Module PKI
	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_beforenm Lib "libsodium" (Buffer As Ptr, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_detached Lib "libsodium" (Buffer As Ptr, MAC As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_detached_afternm Lib "libsodium" (Buffer As Ptr, MAC As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SharedKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_easy Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_easy_afternm Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SharedKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_keypair Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_open_detached_afternm Lib "libsodium" (Buffer As Ptr, Message As Ptr, MAC As Ptr, MessageLength As UInt64, Nonce As Ptr, SharedKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_open_easy Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_open_easy_afternm Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SharedKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_seed_keypair Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr, SeedData As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_scalarmult Lib "libsodium" (Buffer As Ptr, PrivateKey As Ptr, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_scalarmult_base Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_detached Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_ed25519_pk_to_curve25519 Lib "libsodium" (ToEncryptionKey As Ptr, FromSigningKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_ed25519_sk_to_pk Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_ed25519_sk_to_seed Lib "libsodium" (Seed As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_keypair Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_open Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_seed_keypair Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr, SeedData As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_verify_detached Lib "libsodium" (Signature As Ptr, Message As Ptr, MessageLength As UInt64, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function DecryptData(CipherText As MemoryBlock, SenderPublicKey As MemoryBlock, RecipientPrivateKey As libsodium.PKI.EncryptionKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypt the CipherText using the RecipientPrivateKey, and verify it using the SenderPublicKey
		  ' Nonce must be precisely the same as the Nonce used to encrypt the CipherText.
		  ' On error returns Nil.
		  
		  If Nonce.Size <> crypto_box_NONCEBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_MACBYTES)
		  If crypto_box_open_easy(Buffer, CipherText, CipherText.Size, Nonce, SenderPublicKey, RecipientPrivateKey.PrivateKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecryptData(CipherText As MemoryBlock, SharedKey As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypt the CipherText using the XSalsa20 stream cipher with a precalulated SharedKey.
		  ' Nonce must be precisely the same as the Nonce used to encrypt the CipherText. On error
		  ' returns Nil.
		  
		  If Nonce.Size <> crypto_box_NONCEBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_MACBYTES)
		  If crypto_box_open_easy_afternm(Buffer, CipherText, CipherText.Size, Nonce, SharedKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DerivePublicKey(PrivateKeyData As MemoryBlock) As MemoryBlock
		  If PrivateKeyData.Size <> crypto_box_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim pub As New MemoryBlock(crypto_box_PUBLICKEYBYTES)
		  If crypto_scalarmult_base(pub, PrivateKeyData) = 0 Then Return pub
		  
		  
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DeriveSharedKey(RecipientPublicKey As MemoryBlock, SenderPrivateKey As MemoryBlock) As MemoryBlock
		  ' Calculates the shared key from the RecipientPublicKey and SenderPrivateKey, for
		  ' use with the EncryptData and DecryptData methods. This allows the key derivation
		  ' calculation to be performed once rather than on each invocation of EncryptData
		  ' and DecryptData.
		  
		  Dim buffer As New MemoryBlock(crypto_box_BEFORENMBYTES)
		  
		  If crypto_box_beforenm(buffer, RecipientPublicKey, SenderPrivateKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DeriveSharedSecret(RecipientPublicKey As MemoryBlock, SenderPrivateKey As MemoryBlock) As MemoryBlock
		  ' Computes a shared secret given a SenderPrivateKey and RecipientPublicKey.
		  ' The return value represents the X coordinate of a point on the curve. As
		  ' a result, the number of possible keys is limited to the group size (≈2^252),
		  ' and the key distribution is not uniform. For this reason, instead of directly
		  ' using the return value as a shared key, it is recommended to use:
		  '
		  '  GenericHash(return value + RecipientPublicKey + Sender's PUBLIC KEY)
		  
		  Dim buffer As New MemoryBlock(crypto_scalarmult_BYTES)
		  
		  If crypto_scalarmult(buffer, SenderPrivateKey, RecipientPublicKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, RecipientPublicKey As MemoryBlock, SenderPrivateKey As libsodium.PKI.EncryptionKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with the RecipientPublicKey and the specified 24-byte
		  ' Nonce; and then prepends a signature for the ClearText generated using the SenderPrivateKey. On error returns Nil.
		  
		  If Nonce.Size <> crypto_box_NONCEBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_MACBYTES)
		  If crypto_box_easy(buffer, ClearText, ClearText.Size, Nonce, RecipientPublicKey, SenderPrivateKey.PrivateKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, SharedKey As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypt the ClearText using the XSalsa20 stream cipher with a precalulated SharedKey and
		  ' the specified 24-byte Nonce. On error returns Nil.
		  
		  If Nonce.Size <> crypto_box_NONCEBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_MACBYTES)
		  If crypto_box_easy_afternm(buffer, ClearText, ClearText.Size, Nonce, SharedKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RandomKey() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a private key.
		  
		  Return libsodium.RandomBytes(crypto_box_SECRETKEYBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RandomNonce() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a Nonce
		  
		  Return RandomBytes(crypto_box_NONCEBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SignData(Message As MemoryBlock, SecretKey As MemoryBlock, Detached As Boolean = False) As MemoryBlock
		  
		  If SecretKey.Size <> crypto_sign_SECRETKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim signature As MemoryBlock
		  Dim siglen As UInt64
		  If Not Detached Then
		    signature = New MemoryBlock(Message.Size + crypto_sign_BYTES)
		    siglen = signature.Size
		    If crypto_sign(signature, siglen, Message, Message.Size, SecretKey) <> 0 Then signature = Nil
		  Else
		    signature = New MemoryBlock(crypto_sign_BYTES)
		    If crypto_sign_detached(signature, siglen, Message, Message.Size, SecretKey) <> 0 Then signature = Nil
		  End If
		  
		  Return signature.StringValue(0, siglen)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyData(SignedMessage As MemoryBlock, SignerPublicKey As MemoryBlock, DetachedSignature As MemoryBlock = Nil) As Boolean
		  ' Validate a HMAC-SHA512256 authentication code for the Message that was generated using SecretKey
		  
		  If SignerPublicKey.Size <> crypto_sign_PUBLICKEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  Dim sz As UInt64
		  If DetachedSignature = Nil Then
		    Dim tmp As New MemoryBlock(SignedMessage.Size - crypto_sign_BYTES)
		    sz = tmp.Size
		    Return crypto_sign_open(tmp, sz, SignedMessage, SignedMessage.Size, SignerPublicKey) = 0
		  Else
		    Return crypto_sign_verify_detached(DetachedSignature, SignedMessage, SignedMessage.Size, SignerPublicKey) = 0
		  End If
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
End Module
#tag EndModule
