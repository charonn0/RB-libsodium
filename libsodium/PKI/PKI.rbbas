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
		Private Soft Declare Function crypto_sign_ed25519_sk_to_curve25519 Lib "libsodium" (ToEncryptionKey As Ptr, FromSigningKey As Ptr) As Int32
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
		Protected Function DecodeSignature(SigData As MemoryBlock) As MemoryBlock
		  Dim lines() As String = SplitB(SigData, EndOfLine.Windows)
		  If lines(0) <> "-----BEGIN ED25519 SIGNATURE-----" Then Return Nil
		  Dim sig As New MemoryBlock(0)
		  Dim bs As New BinaryStream(sig)
		  Dim i As Integer
		  For i = 1 To UBound(lines)
		    If lines(i) <> "-----END ED25519 SIGNATURE-----" Then
		      bs.Write(lines(i) + EndOfLine.Windows)
		    Else
		      Exit For
		    End If
		  Next
		  bs.Close
		  
		  Return DecodeBase64(sig)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecryptData(CipherText As MemoryBlock, SenderPublicKey As libsodium.PKI.ForeignKey, RecipientPrivateKey As libsodium.PKI.EncryptionKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypts the CipherText using the XSalsa20 stream cipher with a shared key, which is derived
		  ' from the SenderPublicKey and RecipientPrivateKey, and a Nonce. A Poly1305 message authentication
		  ' code is prepended by the EncryptData method and will be validated by this method. The decrypted
		  ' data is returned  on success. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  CheckSize(Nonce, crypto_box_NONCEBYTES)
		  CheckSize(SenderPublicKey.Value, crypto_box_PUBLICKEYBYTES)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_MACBYTES)
		  If crypto_box_open_easy(Buffer, CipherText, CipherText.Size, Nonce, SenderPublicKey.Value, RecipientPrivateKey.PrivateKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecryptData(CipherText As MemoryBlock, SharedKey As libsodium.PKI.SharedSecret, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypts the CipherText using the XSalsa20 stream cipher with a precalulated shared key and a
		  ' Nonce. A Poly1305 message authentication code is prepended by the EncryptData method and will
		  ' be validated by this method. The decrypted data is returned  on success. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  CheckSize(Nonce, crypto_box_NONCEBYTES)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_MACBYTES)
		  If crypto_box_open_easy_afternm(Buffer, CipherText, CipherText.Size, Nonce, SharedKey.Value) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncodeSignature(SigData As MemoryBlock) As MemoryBlock
		  Dim out As New MemoryBlock(0)
		  Dim bs As New BinaryStream(out)
		  bs.Write("-----BEGIN ED25519 SIGNATURE-----" + EndOfLine.Windows)
		  bs.Write(EndOfLine.Windows)
		  bs.Write(EncodeBase64(SigData) + EndOfLine.Windows)
		  bs.Write("-----END ED25519 SIGNATURE-----" + EndOfLine.Windows)
		  bs.Close
		  Return out
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, RecipientPublicKey As libsodium.PKI.ForeignKey, SenderPrivateKey As libsodium.PKI.EncryptionKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with a shared key, which is derived
		  ' from the RecipientPublicKey and SenderPrivateKey, and a Nonce. A Poly1305 message authentication
		  ' code is also generated and prepended to the returned encrypted data. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  CheckSize(Nonce, crypto_box_NONCEBYTES)
		  CheckSize(RecipientPublicKey.Value, crypto_box_PUBLICKEYBYTES)
		  CheckSize(SenderPrivateKey.PrivateKey, crypto_box_SECRETKEYBYTES)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_MACBYTES)
		  If crypto_box_easy(buffer, ClearText, ClearText.Size, Nonce, RecipientPublicKey.Value, SenderPrivateKey.PrivateKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, SharedKey As libsodium.PKI.SharedSecret, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with a precalculated shared key and a
		  ' Nonce. A Poly1305 message authentication code is also generated and prepended to the returned
		  ' encrypted data. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  CheckSize(Nonce, crypto_box_NONCEBYTES)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_MACBYTES)
		  If crypto_box_easy_afternm(buffer, ClearText, ClearText.Size, Nonce, SharedKey.Value) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SignData(Message As MemoryBlock, SenderKey As libsodium.PKI.SigningKey, Detached As Boolean = False) As MemoryBlock
		  ' Generate a Ed25519 signature for the Message using the SenderKey. If Detached=True then
		  ' only the signature is returned; otherwise the signature is prepended to the message and
		  ' both are returned.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
		  
		  CheckSize(SenderKey.PrivateKey, crypto_sign_SECRETKEYBYTES)
		  
		  Dim signature As MemoryBlock
		  Dim siglen As UInt64
		  If Not Detached Then
		    signature = New MemoryBlock(Message.Size + crypto_sign_BYTES)
		    siglen = signature.Size
		    If crypto_sign(signature, siglen, Message, Message.Size, SenderKey.PrivateKey) <> 0 Then signature = Nil
		  Else
		    signature = New MemoryBlock(crypto_sign_BYTES)
		    If crypto_sign_detached(signature, siglen, Message, Message.Size, SenderKey.PrivateKey) <> 0 Then signature = Nil
		  End If
		  
		  If signature <> Nil Then Return signature.StringValue(0, siglen)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyData(SignedMessage As MemoryBlock, SignerPublicKey As libsodium.PKI.ForeignKey) As MemoryBlock
		  ' Validate a Ed25519 signature for the Message that was generated using the signer's PRIVATE key.
		  ' If the signature was not prepended to the message (the default for SignData) then the signature
		  ' must be passed as DetatchedSignature.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
		  
		  
		  CheckSize(SignerPublicKey.Value, crypto_sign_PUBLICKEYBYTES)
		  Dim tmp As New MemoryBlock(SignedMessage.Size - crypto_sign_BYTES)
		  Dim sz As UInt64 = tmp.Size
		  If crypto_sign_open(tmp, sz, SignedMessage, SignedMessage.Size, SignerPublicKey.Value) = 0 Then
		    tmp.Size = sz
		    Return tmp
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyData(SignedMessage As MemoryBlock, SignerPublicKey As libsodium.PKI.ForeignKey, DetachedSignature As MemoryBlock) As Boolean
		  ' Validate a Ed25519 signature for the Message that was generated using the signer's PRIVATE key.
		  ' If the signature was not prepended to the message (the default for SignData) then the signature
		  ' must be passed as DetatchedSignature.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
		  
		  
		  CheckSize(SignerPublicKey.Value, crypto_sign_PUBLICKEYBYTES)
		  Return crypto_sign_verify_detached(DetachedSignature, SignedMessage, SignedMessage.Size, SignerPublicKey.Value) = 0
		  
		End Function
	#tag EndMethod


	#tag Constant, Name = crypto_box_BEFORENMBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_MACBYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_PUBLICKEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_SECRETKEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_SEEDBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_scalarmult_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_sign_BYTES, Type = Double, Dynamic = False, Default = \"64", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_sign_PUBLICKEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_sign_SECRETKEYBYTES, Type = Double, Dynamic = False, Default = \"64", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_sign_SEEDBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN CURVE25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportEncryptionPublicSuffix, Type = String, Dynamic = False, Default = \"-----END CURVE25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPrivatePrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPrivateSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PRIVATE KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPublicPrefix, Type = String, Dynamic = False, Default = \"-----BEGIN ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant

	#tag Constant, Name = ExportSigningPublicSuffix, Type = String, Dynamic = False, Default = \"-----END ED25519 PUBLIC KEY BLOCK-----", Scope = Private
	#tag EndConstant


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
