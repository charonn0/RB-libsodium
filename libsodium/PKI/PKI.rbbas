#tag Module
Protected Module PKI
	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_beforenm Lib "libsodium" (Buffer As Ptr, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_beforenmbytes Lib "libsodium" () As UInt32
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
		Private Soft Declare Function crypto_box_macbytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_noncebytes Lib "libsodium" () As UInt32
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
		Private Soft Declare Function crypto_box_publickeybytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_seal Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_seal_open Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_secretkeybytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_seedbytes Lib "libsodium" () As UInt32
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
		Private Soft Declare Function crypto_scalarmult_bytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_bytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_detached Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_ed25519ph_statebytes Lib "libsodium" () As UInt32
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
		Private Soft Declare Function crypto_sign_final_create Lib "libsodium" (State As Ptr, Signature As Ptr, ByRef SigLength As UInt64, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_final_verify Lib "libsodium" (State As Ptr, Signature As Ptr, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_init Lib "libsodium" (State As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_keypair Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_open Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_publickeybytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_secretkeybytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_seedbytes Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_seed_keypair Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr, SeedData As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_update Lib "libsodium" (State As Ptr, Message As Ptr, MessageLength As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_verify_detached Lib "libsodium" (Signature As Ptr, Message As Ptr, MessageLength As UInt64, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function DecryptData(CipherText As MemoryBlock, SenderPublicKey As libsodium.PKI.ForeignKey, RecipientPrivateKey As libsodium.PKI.EncryptionKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypts the CipherText using the XSalsa20 stream cipher with a shared key, which is derived
		  ' from the SenderPublicKey and RecipientPrivateKey, and a Nonce. A Poly1305 message authentication
		  ' code is prepended by the EncryptData method and will be validated by this method. The decrypted
		  ' data is returned  on success. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  If Left(CipherText, 5) = "-----" Then
		    If Nonce = Nil Then
		      CipherText = libsodium.Exporting.DecodeMessage(CipherText, Nonce)
		    Else
		      CipherText = libsodium.Exporting.DecodeMessage(CipherText)
		    End If
		  End If
		  CheckSize(Nonce, crypto_box_noncebytes)
		  CheckSize(SenderPublicKey.Value, crypto_box_publickeybytes)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_macbytes)
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
		  
		  If Left(CipherText, 5) = "-----" Then
		    If Nonce = Nil Then
		      CipherText = libsodium.Exporting.DecodeMessage(CipherText, Nonce)
		    Else
		      CipherText = libsodium.Exporting.DecodeMessage(CipherText)
		    End If
		  End If
		  CheckSize(Nonce, crypto_box_noncebytes)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_macbytes)
		  If crypto_box_open_easy_afternm(Buffer, CipherText, CipherText.Size, Nonce, SharedKey.Value) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, RecipientPublicKey As libsodium.PKI.ForeignKey, SenderPrivateKey As libsodium.PKI.EncryptionKey, Nonce As MemoryBlock, Exportable As Boolean = False) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with a shared key, which is derived
		  ' from the RecipientPublicKey and SenderPrivateKey, and a Nonce. A Poly1305 message authentication
		  ' code is also generated and prepended to the returned encrypted data. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  If Nonce = Nil And Exportable Then Nonce = SenderPrivateKey.RandomNonce
		  CheckSize(Nonce, crypto_box_noncebytes)
		  CheckSize(RecipientPublicKey.Value, crypto_box_publickeybytes)
		  CheckSize(SenderPrivateKey.PrivateKey, crypto_box_secretkeybytes)
		  If RecipientPublicKey.Type <> ForeignKey.KeyType.Encryption Then Raise New SodiumException(ERR_KEYTYPE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_macbytes)
		  If crypto_box_easy(buffer, ClearText, ClearText.Size, Nonce, RecipientPublicKey.Value, SenderPrivateKey.PrivateKey) = 0 Then
		    If Exportable Then buffer = libsodium.Exporting.EncodeMessage(buffer, Nonce)
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, SharedKey As libsodium.PKI.SharedSecret, Nonce As MemoryBlock, Exportable As Boolean = False) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with a precalculated shared key and a
		  ' Nonce. A Poly1305 message authentication code is also generated and prepended to the returned
		  ' encrypted data. On error returns Nil.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html
		  
		  If Nonce = Nil And Exportable Then Nonce = SharedKey.RandomNonce
		  CheckSize(Nonce, crypto_box_noncebytes)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_macbytes)
		  If crypto_box_easy_afternm(buffer, ClearText, ClearText.Size, Nonce, SharedKey.Value) = 0 Then
		    If Exportable Then buffer = libsodium.Exporting.EncodeMessage(buffer, Nonce)
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SealData(ClearText As MemoryBlock, RecipientPublicKey As libsodium.PKI.ForeignKey, Exportable As Boolean = False) As MemoryBlock
		  ' Seals the ClearText using the XSalsa20 stream cipher with the recipient's public key and an
		  ' ephemeral private key. On error returns Nil.
		  '
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html
		  
		  If RecipientPublicKey.Type <> ForeignKey.KeyType.Encryption Then Raise New SodiumException(ERR_KEYTYPE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_publickeybytes + crypto_box_macbytes)
		  If crypto_box_seal(buffer, ClearText, ClearText.Size, RecipientPublicKey.Value) = 0 Then
		    If Exportable Then buffer = libsodium.Exporting.EncodeMessage(buffer)
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SignData(Algorithm As libsodium.HashType, Message As Readable, SenderKey As libsodium.PKI.SigningKey, Exportable As Boolean = False) As MemoryBlock
		  ' Generate a Ed25519ph signature for the Message using the SenderKey.
		  ' This method is suited for Messages that can't fit into memory.
		  
		  CheckSize(SenderKey.PrivateKey, crypto_sign_secretkeybytes)
		  Dim sigstream As libsodium.PKI.SigningDigest
		  If Algorithm = HashType.SHA256 Then ' ignored
		    sigstream = New libsodium.PKI.SigningDigest()
		  Else
		    sigstream = New libsodium.PKI.SigningDigest(Algorithm)
		  End If
		  
		  Do Until Message.EOF
		    sigstream.Process(Message.Read(1024 * 1024 * 32))
		  Loop
		  Dim signature As MemoryBlock = sigstream.Sign(SenderKey)
		  Dim metadata As Dictionary
		  If Exportable Then
		    If Algorithm = HashType.SHA512 Then
		      metadata = New Dictionary("Alg":"SHA512")
		    ElseIf Algorithm = HashType.Generic Then
		      metadata = New Dictionary("Alg":"blake2b")
		    End If
		    Dim type As libsodium.Exporting.ExportableType = libsodium.Exporting.ExportableType.SignatureDigest
		    signature = libsodium.Exporting.Export(signature, type, Nil, ResourceLimits.Interactive, metadata)
		  End If
		  Return signature
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SignData(Message As MemoryBlock, SenderKey As libsodium.PKI.SigningKey, Detached As Boolean = False, Exportable As Boolean = False) As MemoryBlock
		  ' Generate a Ed25519 signature for the Message using the SenderKey. If Detached=True then
		  ' only the signature is returned; otherwise the signature is prepended to the message and
		  ' both are returned.
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
		  
		  CheckSize(SenderKey.PrivateKey, crypto_sign_secretkeybytes)
		  
		  Dim signature As MemoryBlock
		  Dim siglen As UInt64
		  If Not Detached Then
		    signature = New MemoryBlock(Message.Size + crypto_sign_bytes)
		    siglen = signature.Size
		    If crypto_sign(signature, siglen, Message, Message.Size, SenderKey.PrivateKey) <> 0 Then Return Nil
		  Else
		    signature = New MemoryBlock(crypto_sign_bytes)
		    If crypto_sign_detached(signature, siglen, Message, Message.Size, SenderKey.PrivateKey) <> 0 Then Return Nil
		  End If
		  
		  signature = signature.StringValue(0, siglen)
		  If Exportable Then signature = libsodium.Exporting.Export(signature, libsodium.Exporting.ExportableType.Signature)
		  Return signature
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SignData(Message As Readable, SenderKey As libsodium.PKI.SigningKey, Exportable As Boolean = False) As MemoryBlock
		  ' Generate a Ed25519ph signature for the Message using the SenderKey.
		  ' This method is suited for Messages that can't fit into memory.
		  
		  Return SignData(HashType.SHA256, Message, SenderKey, Exportable)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function UnsealData(SealedBox As MemoryBlock, RecipientPrivateKey As libsodium.PKI.EncryptionKey) As MemoryBlock
		  ' Decrypts the SealedBox using the XSalsa20 stream cipher with the recipient's private key. The decrypted
		  ' data is returned  on success. On error returns Nil.
		  '
		  ' See: https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html
		  
		  If Left(SealedBox, 5) = "-----" Then SealedBox = libsodium.Exporting.DecodeMessage(SealedBox)
		  Dim buffer As New MemoryBlock(SealedBox.Size - crypto_box_publickeybytes - crypto_box_macbytes)
		  If crypto_box_seal_open(Buffer, SealedBox, SealedBox.Size, RecipientPrivateKey.Publickey, RecipientPrivateKey.PrivateKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyData(SignedMessage As MemoryBlock, SignerPublicKey As libsodium.PKI.ForeignKey) As MemoryBlock
		  ' Validate a Ed25519 signature for the Message that was generated using the signer's PRIVATE key.
		  ' The signature is expected to be prepended to the message (the default for SignData).
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.VerifyData
		  
		  
		  CheckSize(SignerPublicKey.Value, crypto_sign_publickeybytes)
		  If SignerPublicKey.Type <> ForeignKey.KeyType.Signature Then Raise New SodiumException(ERR_KEYTYPE_MISMATCH)
		  
		  If Left(SignedMessage, 5) = "-----" Then SignedMessage = libsodium.Exporting.Import(SignedMessage)
		  Dim tmp As New MemoryBlock(SignedMessage.Size - crypto_sign_bytes)
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
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.VerifyData
		  
		  
		  If SignerPublicKey.Type <> ForeignKey.KeyType.Signature Then Raise New SodiumException(ERR_KEYTYPE_MISMATCH)
		  CheckSize(SignerPublicKey.Value, crypto_sign_publickeybytes)
		  If Left(DetachedSignature, 5) = "-----" Then DetachedSignature = libsodium.Exporting.Import(DetachedSignature)
		  Return crypto_sign_verify_detached(DetachedSignature, SignedMessage, SignedMessage.Size, SignerPublicKey.Value) = 0
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyData(SignedMessage As Readable, SignerPublicKey As libsodium.PKI.ForeignKey, Signature As MemoryBlock) As Boolean
		  ' Verify a Ed25519ph signature for the Message using the SenderKey.
		  ' This method is suited for Messages that can't fit into memory.
		  
		  If SignerPublicKey.Type <> ForeignKey.KeyType.Signature Then Raise New SodiumException(ERR_KEYTYPE_MISMATCH)
		  CheckSize(SignerPublicKey.Value, crypto_sign_publickeybytes)
		  Dim metadata As Dictionary
		  If Left(Signature, 5) = "-----" Then Signature = libsodium.Exporting.Import(Signature, metadata)
		  Dim sigstream As libsodium.PKI.SigningDigest
		  
		  If metadata = Nil Or metadata.Lookup("Alg", "") = "" Then
		    sigstream = New libsodium.PKI.SigningDigest()
		  ElseIf metadata.Lookup("Alg", "") = "SHA512" Then
		    sigstream = New libsodium.PKI.SigningDigest(HashType.SHA512)
		  ElseIf metadata.Lookup("Alg", "") = "blake2b" Then
		    sigstream = New libsodium.PKI.SigningDigest(HashType.Generic)
		  Else
		    Return False
		  End If
		  
		  Do Until SignedMessage.EOF
		    sigstream.Process(SignedMessage.Read(1024 * 1024 * 32))
		  Loop
		  Return sigstream.Verify(SignerPublicKey, Signature)
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
