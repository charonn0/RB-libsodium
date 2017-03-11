#tag Module
Protected Module SKI
	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_aead_aes256gcm_decrypt Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Reserved As Ptr, CipherText As Ptr, CipherTextSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_aead_aes256gcm_encrypt Lib "libsodium" (Buffer As Ptr, BufferSize As UInt64, Message As Ptr, MessageSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64, Reserved As Ptr, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_aead_chacha20poly1305_decrypt Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Reserved As Ptr, CipherText As Ptr, CipherTextSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_aead_chacha20poly1305_encrypt Lib "libsodium" (Buffer As Ptr, BufferSize As UInt64, Message As Ptr, MessageSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64, Reserved As Ptr, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_aead_chacha20poly1305_ietf_decrypt Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Reserved As Ptr, CipherText As Ptr, CipherTextSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_aead_chacha20poly1305_ietf_encrypt Lib "libsodium" (Buffer As Ptr, BufferSize As UInt64, Message As Ptr, MessageSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64, Reserved As Ptr, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_verify Lib "libsodium" (Signature As Ptr, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_easy Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_open_easy Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function DecryptData(CipherText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Decrypts the CipherText using the XSalsa20 stream cipher with the specified Key and Nonce. A
		  ' Poly1305 message authentication code is prepended by the EncryptData method and will be
		  ' validated by this method. The decrypted data is returned on success. On error returns Nil.
		  '
		  ' See: 
		  ' https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html#combined-mode
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.DecryptData
		  
		  Return DecryptData(CipherText, Key.Value, Nonce)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function DecryptData(CipherText As MemoryBlock, Key As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  CheckSize(Nonce, crypto_secretbox_NONCEBYTES)
		  CheckSize(Key, crypto_secretbox_KEYBYTES)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_secretbox_MACBYTES)
		  If crypto_secretbox_open_easy(Buffer, CipherText, CipherText.Size, Nonce, Key) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecryptDataAEAD(CipherText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock, Type As libsodium.SKI.AEADType = libsodium.SKI.AEADType.ChaCha20Poly1305) As MemoryBlock
		  ' Authenticated Encryption with Additional Data (AEAD) verifies that the CipherText includes a valid
		  ' message authentication code using the SecretKey, a public nonce, and optional additional data. If
		  ' the verification succeeds, the function returns the decrypted message. On error returns Nil.
		  
		  Select Case Type
		  Case AEADType.ChaCha20Poly1305
		    Return DecryptDataAEAD_ChaCha20Poly1305(CipherText, Key, Nonce, AdditionalData)
		    
		  Case AEADType.ChaCha20Poly1305_IETF
		    Return DecryptDataAEAD_ChaCha20Poly1305_IETF(CipherText, Key, Nonce, AdditionalData)
		    
		  Case AEADType.AES256GCM
		    Return DecryptDataAEAD_AES256GCM(CipherText, Key, Nonce, AdditionalData)
		    
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function DecryptDataAEAD_AES256GCM(CipherText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock) As MemoryBlock
		  Static HasAES256GCM As Boolean = libsodium.Version.HasAES256GCM
		  If Not HasAES256GCM Then Raise New PlatformNotSupportedException
		  CheckSize(Key.Value, crypto_aead_aes256gcm_KEYBYTES)
		  CheckSize(Nonce, crypto_aead_aes256gcm_NPUBBYTES)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_aead_aes256gcm_ABYTES)
		  Dim buffersz As UInt64 = buffer.Size
		  
		  If AdditionalData <> Nil Then
		    If crypto_aead_aes256gcm_decrypt(Buffer, buffersz, Nil, CipherText, CipherText.Size, _
		      AdditionalData, AdditionalData.Size, Nonce, Key.Value) <> 0 Then Return Nil
		    Else
		      If crypto_aead_aes256gcm_decrypt(Buffer, buffersz, Nil, CipherText, CipherText.Size, _
		        Nil, 0, Nonce, Key.Value) <> 0 Then Return Nil
		      End If
		      Return buffer.StringValue(0, buffersz)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function DecryptDataAEAD_ChaCha20Poly1305(CipherText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock) As MemoryBlock
		  CheckSize(Key.Value, crypto_aead_chacha20poly1305_KEYBYTES)
		  CheckSize(Nonce, crypto_aead_chacha20poly1305_NPUBBYTES)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_aead_chacha20poly1305_ABYTES)
		  Dim buffersz As UInt64 = buffer.Size
		  
		  If AdditionalData <> Nil Then
		    If crypto_aead_chacha20poly1305_decrypt(Buffer, buffersz, Nil, CipherText, CipherText.Size, _
		      AdditionalData, AdditionalData.Size, Nonce, Key.Value) <> 0 Then Return Nil
		    Else
		      If crypto_aead_chacha20poly1305_decrypt(Buffer, buffersz, Nil, CipherText, CipherText.Size, _
		        Nil, 0, Nonce, Key.Value) <> 0 Then Return Nil
		      End If
		      Return buffer.StringValue(0, buffersz)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function DecryptDataAEAD_ChaCha20Poly1305_IETF(CipherText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock) As MemoryBlock
		  CheckSize(Key.Value, crypto_aead_chacha20poly1305_IETF_KEYBYTES)
		  CheckSize(Nonce, crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_aead_chacha20poly1305_IETF_ABYTES)
		  Dim buffersz As UInt64 = buffer.Size
		  
		  If AdditionalData <> Nil Then
		    If crypto_aead_chacha20poly1305_ietf_decrypt(Buffer, buffersz, Nil, CipherText, CipherText.Size, _
		      AdditionalData, AdditionalData.Size, Nonce, Key.Value) <> 0 Then Return Nil
		    Else
		      If crypto_aead_chacha20poly1305_ietf_decrypt(Buffer, buffersz, Nil, CipherText, CipherText.Size, _
		        Nil, 0, Nonce, Key.Value) <> 0 Then Return Nil
		      End If
		      Return buffer.StringValue(0, buffersz)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with the specified Key and Nonce. A
		  ' Poly1305 message authentication code is also generated and prepended to the returned encrypted
		  ' data. On error returns Nil.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html#combined-mode
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.EncryptData
		  
		  Return EncryptData(ClearText, Key.Value, Nonce)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function EncryptData(ClearText As MemoryBlock, Key As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  CheckSize(Nonce, crypto_secretbox_NONCEBYTES)
		  CheckSize(Key, crypto_secretbox_KEYBYTES)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_secretbox_MACBYTES)
		  If crypto_secretbox_easy(buffer, ClearText, ClearText.Size, Nonce, Key) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptDataAEAD(ClearText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock, Type As libsodium.SKI.AEADType = libsodium.SKI.AEADType.ChaCha20Poly1305) As MemoryBlock
		  ' Authenticated Encryption with Additional Data (AEAD) encrypts the ClearText using a secret key
		  ' and public nonce. A message authentication code for both the encrypted message and the optional
		  ' AdditionalData is computed and prepended to the encrypted message. AdditionalData may be Nil
		  ' if no additional data are required.
		  '
		  ' The public nonce should never ever be reused with the same key. The recommended way to generate
		  ' it is to use libsodium.RandomBytes for the first message, and increment it for each subsequent
		  ' message using the same key.
		  
		  Select Case Type
		  Case AEADType.ChaCha20Poly1305
		    Return EncryptDataAEAD_ChaCha20Poly1305(ClearText, Key, Nonce, AdditionalData)
		    
		  Case AEADType.ChaCha20Poly1305_IETF
		    Return EncryptDataAEAD_ChaCha20Poly1305_IETF(ClearText, Key, Nonce, AdditionalData)
		    
		  Case AEADType.AES256GCM
		    Return EncryptDataAEAD_AES256GCM(ClearText, Key, Nonce, AdditionalData)
		    
		  End Select
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function EncryptDataAEAD_AES256GCM(ClearText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock) As MemoryBlock
		  Static HasAES256GCM As Boolean = libsodium.Version.HasAES256GCM
		  If Not HasAES256GCM Then Raise New PlatformNotSupportedException
		  CheckSize(Key.Value, crypto_aead_aes256gcm_KEYBYTES)
		  CheckSize(Nonce, crypto_aead_aes256gcm_NPUBBYTES)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_aead_chacha20poly1305_IETF_ABYTES)
		  If AdditionalData <> Nil Then
		    If crypto_aead_aes256gcm_encrypt(buffer, buffer.Size, ClearText, ClearText.Size, _
		      AdditionalData, AdditionalData.Size, Nil, Nonce, Key.Value) = 0 Then Return buffer
		    Else
		      If crypto_aead_aes256gcm_encrypt(buffer, buffer.Size, ClearText, ClearText.Size, _
		        Nil, 0, Nil, Nonce, Key.Value) = 0 Then Return buffer
		      End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function EncryptDataAEAD_ChaCha20Poly1305(ClearText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock) As MemoryBlock
		  CheckSize(Key.Value, crypto_aead_chacha20poly1305_KEYBYTES)
		  CheckSize(Nonce, crypto_aead_chacha20poly1305_NPUBBYTES)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_aead_chacha20poly1305_ABYTES)
		  If AdditionalData <> Nil Then
		    If crypto_aead_chacha20poly1305_encrypt(buffer, buffer.Size, ClearText, ClearText.Size, _
		      AdditionalData, AdditionalData.Size, Nil, Nonce, Key.Value) = 0 Then Return buffer
		    Else
		      If crypto_aead_chacha20poly1305_encrypt(buffer, buffer.Size, ClearText, ClearText.Size, _
		        Nil, 0, Nil, Nonce, Key.Value) = 0 Then Return buffer
		      End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function EncryptDataAEAD_ChaCha20Poly1305_IETF(ClearText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, AdditionalData As MemoryBlock) As MemoryBlock
		  CheckSize(Key.Value, crypto_aead_chacha20poly1305_IETF_KEYBYTES)
		  CheckSize(Nonce, crypto_aead_chacha20poly1305_IETF_NPUBBYTES)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_aead_chacha20poly1305_IETF_ABYTES)
		  If AdditionalData <> Nil Then
		    If crypto_aead_chacha20poly1305_ietf_encrypt(buffer, buffer.Size, ClearText, ClearText.Size, _
		      AdditionalData, AdditionalData.Size, Nil, Nonce, Key.Value) = 0 Then Return buffer
		    Else
		      If crypto_aead_chacha20poly1305_ietf_encrypt(buffer, buffer.Size, ClearText, ClearText.Size, _
		        Nil, 0, Nil, Nonce, Key.Value) = 0 Then Return buffer
		      End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GenerateMAC(Message As MemoryBlock, Key As libsodium.SKI.SecretKey) As MemoryBlock
		  ' Generate a HMAC-SHA512256 authentication code for the Message using SecretKey.
		  ' See: https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
		  
		  CheckSize(Key.Value, crypto_auth_KEYBYTES)
		  
		  Dim signature As New MemoryBlock(crypto_auth_BYTES)
		  If crypto_auth(signature, Message, Message.Size, Key.Value) = 0 Then
		    Return signature
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyMAC(MAC As MemoryBlock, Message As MemoryBlock, Key As libsodium.SKI.SecretKey) As Boolean
		  ' Validate a HMAC-SHA512256 authentication code for the Message that was generated using SecretKey
		  ' See: https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
		  
		  CheckSize(Key.Value, crypto_auth_KEYBYTES)
		  
		  Return crypto_auth_verify(MAC, Message, Message.Size, Key.Value) = 0
		End Function
	#tag EndMethod


	#tag Constant, Name = crypto_aead_aes256gcm_ABYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_aes256gcm_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_aes256gcm_NPUBBYTES, Type = Double, Dynamic = False, Default = \"12", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_chacha20poly1305_ABYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_chacha20poly1305_IETF_ABYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_chacha20poly1305_IETF_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_chacha20poly1305_IETF_NPUBBYTES, Type = Double, Dynamic = False, Default = \"12", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_chacha20poly1305_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_aead_chacha20poly1305_NPUBBYTES, Type = Double, Dynamic = False, Default = \"8", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_auth_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_auth_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_secretbox_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_secretbox_MACBYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_secretbox_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
	#tag EndConstant


	#tag Enum, Name = AEADType, Type = Integer, Flags = &h1
		ChaCha20Poly1305
		  ChaCha20Poly1305_IETF
		AES256GCM
	#tag EndEnum


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
