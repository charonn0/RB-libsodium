#tag Module
Protected Module libsodium
	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, SymmetricKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_verify Lib "libsodium" (Signature As Ptr, Message As Ptr, MessageLength As UInt64, SymmetricKey As Ptr) As Int32
	#tag EndExternalMethod

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

	#tag Method, Flags = &h21
		Private Function crypto_box_MACBYTES() As UInt32
		  Return crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES
		End Function
	#tag EndMethod

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
		Private Soft Declare Function crypto_generichash_final Lib "libsodium" (State As Ptr, OutputBuffer As Ptr, OutputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_init Lib "libsodium" (State As Ptr, Key As Ptr, KeySize As Int64, OutLength As Int64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_statebytes Lib "libsodium" () As UInt64
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_update Lib "libsodium" (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_final Lib "libsodium" (State As Ptr, OutputBuffer As Ptr, OutputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_init Lib "libsodium" (State As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_update Lib "libsodium" (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_final Lib "libsodium" (State As Ptr, OutputBuffer As Ptr, OutputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_init Lib "libsodium" (State As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_update Lib "libsodium" (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash Lib "libsodium" (OutBuffer As Ptr, OutSize As UInt64, Passwd As Ptr, PasswdSize As UInt64, SaltBuffer As Ptr, OpsLimit As UInt64, MemLimit As UInt64, Algorithm As Integer) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_scalarmult Lib "libsodium" (Buffer As Ptr, PrivateKey As Ptr, PublicKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_scalarmult_base Lib "libsodium" (PublicKey As Ptr, PrivateKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign Lib "libsodium" (Buffer As Ptr, BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_sign_detached Lib "libsodium" (Buffer As Ptr, ByRef BufferSize As UInt64, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
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
		Protected Function DecodeHex(HexData As MemoryBlock, IgnoredChars As String = "") As MemoryBlock
		  ' decodes ASCII hexadecimal to Binary
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim output As New MemoryBlock(HexData.Size * 2 + 1)
		  Dim endhex As Ptr
		  Dim ign As MemoryBlock = IgnoredChars + Chr(0)
		  Dim sz As UInt32 = output.Size
		  If sodium_hex2bin(output, output.Size, HexData, HexData.Size, ign, sz, endhex) <> 0 Then Return Nil
		  Return output.StringValue(0, sz)
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
		Protected Function EncodeHex(BinaryData As MemoryBlock) As MemoryBlock
		  ' Encodes the BinaryData as ASCII hexadecimal
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim output As New MemoryBlock(BinaryData.Size * 2 + 1)
		  If sodium_bin2hex(output, output.Size, BinaryData, BinaryData.Size) = Nil Then Return Nil
		  Return output.CString(0).Uppercase
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
		Protected Function GenericHash(InputData As MemoryBlock, Key As String = "") As String
		  ' Generates a 512-bit digest of the InputData, optionally using the specified key.
		  
		  Dim h As GenericHashDigest
		  If Key = "" Then
		    h = New GenericHashDigest(Key)
		  Else
		    h = New GenericHashDigest()
		  End If
		  h.Process(InputData)
		  Return h.Value
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

	#tag Method, Flags = &h1
		Protected Function GetSharedSecret(RecipientPublicKey As MemoryBlock, SenderPrivateKey As MemoryBlock) As MemoryBlock
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
		Protected Function IsAvailable() As Boolean
		  ' Returns True if libsodium is available.
		  
		  Static available As Boolean
		  
		  If Not available Then available = System.IsFunctionAvailable("sodium_init", "libsodium")
		  If available Then 
		    If sodium_init() = -1 Then available = False
		  End If
		  Return available
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RandomBytes(Count As UInt64) As MemoryBlock
		  ' Returns a MemoryBlock filled with Count bytes of cryptographically random data.
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim mb As New MemoryBlock(Count)
		  randombytes_buf(mb, mb.Size)
		  Return mb
		End Function
	#tag EndMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub randombytes_buf Lib "libsodium" (Buffer As Ptr, BufferSize As UInt64)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function randombytes_random Lib "libsodium" () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function randombytes_uniform Lib "libsodium" (UpperBound As UInt32) As UInt32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function RandomKey() As MemoryBlock
		  ' Returns 32 random bytes that are suitable to be used as a secret key.
		  
		  Return RandomBytes(crypto_box_SECRETKEYBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RandomNonce() As MemoryBlock
		  ' Returns 24 random bytes that are suitable to be used as a Nonce for EncryptData.
		  
		  Return RandomBytes(crypto_box_NONCEBYTES)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RandomUInt32(Optional UpperBound As UInt32) As UInt32
		  ' Returns a random UInt32. If UpperBound is specified then the value will be 
		  ' less-than or equal-to UpperBound
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If UpperBound = 0 Then
		    Return randombytes_random()
		  Else
		    Return randombytes_uniform(UpperBound)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SignData(Message As MemoryBlock, SymmetricKey As MemoryBlock) As MemoryBlock
		  ' Generate a signature for the Message using SymmetricKey
		  
		  If SymmetricKey.Size <> crypto_auth_KEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Dim signature As New MemoryBlock(crypto_auth_BYTES)
		  If crypto_auth(signature, Message, Message.Size, SymmetricKey) <> 0 Then Return Nil
		  Return signature
		End Function
	#tag EndMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_add Lib "libsodium" (BufferA As Ptr, BufferB As Ptr, Length As UInt64)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_allocarray Lib "libsodium" (Count As UInt64, FieldSize As UInt64) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_bin2hex Lib "libsodium" (HexBuffer As Ptr, HexBufferLength As UInt32, BinBuffer As Ptr, BinBufferLength As UInt32) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_compare Lib "libsodium" (Buffer1 As Ptr, Buffer2 As Ptr, Lenfth As UInt64) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_free Lib "libsodium" (DataPtr As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_hex2bin Lib "libsodium" (BinBuffer As Ptr, BinBufferMaxLength As UInt32, HexBuffer As Ptr, HexBufferLength As UInt32, IgnoreChars As Ptr, ByRef BinBufferLength As UInt32, ByRef HexEnd As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_increment Lib "libsodium" (Number As Ptr, Length As UInt64)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_init Lib "libsodium" () As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_malloc Lib "libsodium" (Length As UInt64) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_memcmp Lib "libsodium" (Buffer1 As Ptr, Buffer2 As Ptr, Length As UInt64) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_memzero Lib "libsodium" (DataPtr As Ptr, Length As UInt64)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mlock Lib "libsodium" (Address As Ptr, Length As UInt64) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mprotect_noaccess Lib "libsodium" (DataPtr As Ptr) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mprotect_readonly Lib "libsodium" (DataPtr As Ptr) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mprotect_readwrite Lib "libsodium" (DataPtr As Ptr) As Integer
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_munlock Lib "libsodium" (Address As Ptr, Length As UInt64) As Integer
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function StrComp(String1 As String, String2 As String) As Boolean
		  ' Performs a constant-time binary comparison of the strings, and returns True if they are identical.
		  
		  Dim mb1 As MemoryBlock = String1
		  Dim mb2 As MemoryBlock = String2
		  Return sodium_memcmp(mb1, mb2, Max(mb1.Size, mb2.Size)) = 0
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyMAC(MAC As MemoryBlock, Message As MemoryBlock, SecretKey As MemoryBlock) As Boolean
		  ' Validate an authentication code for the Message that was generated using SecretKey
		  
		  If SecretKey.Size <> crypto_auth_KEYBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		  
		  Return crypto_auth_verify(MAC, Message, Message.Size, SecretKey) = 0
		End Function
	#tag EndMethod


	#tag Constant, Name = crypto_auth_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_auth_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_BEFORENMBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_BOXZEROBYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_PUBLICKEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_SECRETKEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_SEEDBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_box_ZEROBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_generichash_BYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_generichash_BYTES_MAX, Type = Double, Dynamic = False, Default = \"64", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_generichash_BYTES_MIN, Type = Double, Dynamic = False, Default = \"16", Scope = Private
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

	#tag Constant, Name = ERR_CANT_ALLOC, Type = Double, Dynamic = False, Default = \"-5", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_COMPUTATION_FAILED, Type = Double, Dynamic = False, Default = \"-12", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_INIT_FAILED, Type = Double, Dynamic = False, Default = \"-2", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_INVALID_STATE, Type = Double, Dynamic = False, Default = \"-11", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_KEYDERIVE_FAILED, Type = Double, Dynamic = False, Default = \"-15", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_KEYGEN_FAILED, Type = Double, Dynamic = False, Default = \"-14", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_LOCK_DENIED, Type = Double, Dynamic = False, Default = \"-9", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_OUT_OF_BOUNDS, Type = Double, Dynamic = False, Default = \"-10", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_PROTECT_FAILED, Type = Double, Dynamic = False, Default = \"-4", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_READ_DENIED, Type = Double, Dynamic = False, Default = \"-7", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_SIZE_MISMATCH, Type = Double, Dynamic = False, Default = \"-13", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_TOO_LARGE, Type = Double, Dynamic = False, Default = \"-6", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_UNAVAILABLE, Type = Double, Dynamic = False, Default = \"-3", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_WRITE_DENIED, Type = Double, Dynamic = False, Default = \"-8", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = STRICT_CONVERT, Type = Boolean, Dynamic = False, Default = \"False", Scope = Private
	#tag EndConstant


	#tag Enum, Name = ProtectionLevel, Flags = &h1
		ReadWrite
		  ReadOnly
		NoAccess
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
