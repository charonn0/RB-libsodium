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
		Private Soft Declare Function crypto_box_open_detached_afternm Lib "libsodium" (Buffer As Ptr, Message As Ptr, MAC As Ptr, MessageLength As UInt64, Nonce As Ptr, SharedKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_open_easy Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_box_open_easy_afternm Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SharedKey As Ptr) As Int32
	#tag EndExternalMethod

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
		Protected Function DecryptData(CipherText As MemoryBlock, RecipientPrivateKey As MemoryBlock, SenderPublicKey As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypt the CipherText using the RecipientPrivateKey, and verify it using the SenderPublicKey
		  ' Nonce must be precisely the same as the Nonce used to encrypt the CipherText.
		  ' On error returns Nil.
		  
		  If Nonce.Size <> crypto_box_NONCEBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_box_MACBYTES)
		  If crypto_box_open_easy(Buffer, CipherText, CipherText.Size, Nonce, SenderPublicKey, RecipientPrivateKey) <> 0 Then Return Nil
		  
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
		Protected Function EncryptData(ClearText As MemoryBlock, RecipientPublicKey As MemoryBlock, SenderPrivateKey As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with the RecipientPublicKey and the specified 24-byte
		  ' Nonce; and then prepends a signature for the ClearText generated using the SenderPrivateKey. On error returns Nil.
		  
		  If Nonce.Size <> crypto_box_NONCEBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_box_MACBYTES)
		  If crypto_box_easy(buffer, ClearText, ClearText.Size, Nonce, RecipientPublicKey, SenderPrivateKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GetSharedKey(RecipientPublicKey As MemoryBlock, SenderPrivateKey As MemoryBlock) As MemoryBlock
		  ' Calculates the shared key from the RecipientPublicKey and SenderPrivateKey, for
		  ' use with the EncryptData and DecryptData methods. This allows the key derivation
		  ' calculation to be performed once rather than on each invocation of EncryptData
		  ' and DecryptData.
		  
		  Dim buffer As New MemoryBlock(crypto_box_BEFORENMBYTES)
		  
		  If crypto_box_beforenm(buffer, RecipientPublicKey, SenderPrivateKey) <> 0 Then Return Nil
		  
		  Return buffer
		End Function
	#tag EndMethod


End Module
#tag EndModule
