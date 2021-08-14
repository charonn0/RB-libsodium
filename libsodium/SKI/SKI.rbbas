#tag Module
Protected Module SKI
	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth Lib sodium (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_bytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_verify Lib sodium (Signature As Ptr, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_easy Lib sodium (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_macbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_noncebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretbox_open_easy Lib sodium (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, Nonce As Ptr, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_abytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_headerbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_init_pull Lib sodium (State As Ptr, Header As Ptr, Key As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_init_push Lib sodium (State As Ptr, Header As Ptr, Key As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub crypto_secretstream_xchacha20poly1305_keygen Lib sodium (Key As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_pull Lib sodium (State As Ptr, Buffer As Ptr, ByRef BufferSize As UInt64, ByRef Tag As UInt8, CipherText As Ptr, CipherTextSize As UInt64, AdditionalData As Ptr, AdditionalDataSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_push Lib sodium (State As Ptr, Buffer As Ptr, ByRef BufferLength As UInt64, Message As Ptr, MessageLength As UInt64, AdditionalData As Ptr, AdditionalDataLength As UInt64, Tag As UInt8) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub crypto_secretstream_xchacha20poly1305_rekey Lib sodium (State As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_secretstream_xchacha20poly1305_statebytes Lib sodium () As UInt32
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
		  If Left(CipherText, 5) = "-----" Then
		    If Nonce = Nil Then
		      CipherText = libsodium.Exporting.DecodeMessage(CipherText, Nonce)
		    Else
		      CipherText = libsodium.Exporting.DecodeMessage(CipherText)
		    End If
		  End If
		  CheckSize(Nonce, crypto_secretbox_noncebytes)
		  CheckSize(Key, crypto_secretbox_keybytes)
		  
		  Dim buffer As New MemoryBlock(CipherText.Size - crypto_secretbox_macbytes)
		  If crypto_secretbox_open_easy(Buffer, CipherText, CipherText.Size, Nonce, Key) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncryptData(ClearText As MemoryBlock, Key As libsodium.SKI.SecretKey, Nonce As MemoryBlock, Exportable As Boolean = False) As MemoryBlock
		  ' Encrypts the ClearText using the XSalsa20 stream cipher with the specified Key and Nonce. A
		  ' Poly1305 message authentication code is also generated and prepended to the returned encrypted
		  ' data. On error returns Nil.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html#combined-mode
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.EncryptData
		  
		  If Nonce = Nil And Exportable Then Nonce = Key.RandomNonce
		  Return EncryptData(ClearText, Key.Value, Nonce, Exportable)
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function EncryptData(ClearText As MemoryBlock, Key As MemoryBlock, Nonce As MemoryBlock, Exportable As Boolean = False) As MemoryBlock
		  CheckSize(Nonce, crypto_secretbox_noncebytes)
		  CheckSize(Key, crypto_secretbox_keybytes)
		  
		  Dim buffer As New MemoryBlock(ClearText.Size + crypto_secretbox_macbytes)
		  If crypto_secretbox_easy(buffer, ClearText, ClearText.Size, Nonce, Key) = 0 Then
		    If Exportable Then buffer = libsodium.Exporting.EncodeMessage(buffer, Nonce)
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GenerateMAC(Message As MemoryBlock, Key As libsodium.SKI.SecretKey, Exportable As Boolean = False) As MemoryBlock
		  ' Generate a HMAC-SHA512256 authentication code for the Message using SecretKey.
		  ' See: https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
		  
		  CheckSize(Key.Value, crypto_auth_keybytes)
		  
		  Dim signature As New MemoryBlock(crypto_auth_bytes)
		  If crypto_auth(signature, Message, Message.Size, Key.Value) = 0 Then
		    If Exportable Then signature = libsodium.Exporting.Export(signature, ExportableType.HMAC)
		    Return signature
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyMAC(MAC As MemoryBlock, Message As MemoryBlock, Key As libsodium.SKI.SecretKey) As Boolean
		  ' Validate a HMAC-SHA512256 authentication code for the Message that was generated using SecretKey
		  ' See: https://download.libsodium.org/doc/secret-key_cryptography/secret-key_authentication.html
		  
		  CheckSize(Key.Value, crypto_auth_keybytes)
		  If Left(MAC, 5) = "-----" Then MAC = libsodium.Exporting.Import(MAC)
		  If Left(Message, 5) = "-----" Then Message = libsodium.Exporting.Import(Message)
		  Return crypto_auth_verify(MAC, Message, Message.Size, Key.Value) = 0
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
