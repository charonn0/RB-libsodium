#tag Module
Protected Module libsodium
	#tag Method, Flags = &h1
		Protected Function Argon2(InputData As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive) As String
		  ' Generates an Argon2 digest of the InputData
		  ' https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html
		  
		  Dim p As New libsodium.Password(InputData)
		  Return p.GenerateHash(Password.ALG_ARGON2, Limits)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Argon2Verify(InputData As MemoryBlock, HashValue As MemoryBlock) As Boolean
		  ' Verifies an Argon2 digest of the InputData
		  ' https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html
		  
		  Dim p As New libsodium.Password(InputData)
		  Return p.VerifyHash(HashValue, Password.ALG_ARGON2)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub CheckSize(Size As Int64, Expected As Int64, Upperbound As Int64 = 0)
		  Dim err As SodiumException
		  Select Case True
		  Case Upperbound > 0 And (Size > Upperbound Or Size < Expected)
		    err = New SodiumException(ERR_OUT_OF_RANGE)
		    err.Message = err.Message + " (Needs: " + Format(Expected, "-############0") + "-" + Format(Upperbound, "-############0") + "; Got: " + Format(Size, "-############0") + ")"
		  Case Size <> Expected And Upperbound = 0
		    err = New SodiumException(ERR_SIZE_MISMATCH)
		    err.Message = err.Message + " (Needs: " + Format(Expected, "-############0") + "; Got: " + Format(Size, "-############0") + ")"
		  End Select
		  
		  If err <> Nil Then Raise err
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub CheckSize(Data As MemoryBlock, Expected As Int64, Upperbound As Int64 = 0)
		  If Data <> Nil Then CheckSize(Data.Size, Expected, Upperbound)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function CombineNonce(Nonce1 As MemoryBlock, Nonce2 As MemoryBlock, DoSubtraction As Boolean = False) As MemoryBlock
		  ' Combines Nonce1 with Nonce2 in constant time. If DoSubtraction=False then
		  ' the combination formula is (Nonce1 + Nonce2) mod 2^(8*len). Otherwise the
		  ' formula is (Nonce1 - Nonce2) mod 2^(8*len).
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.CombineNonce
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If Nonce1.Size < 0 Or Nonce2.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED)
		  
		  Dim output As New MemoryBlock(Nonce1.Size)
		  output.StringValue(0, output.Size) = Nonce1.StringValue(0, Nonce1.Size)
		  If Not DoSubtraction Then
		    sodium_add(output, Nonce2, Max(output.Size, Nonce2.Size))
		  ElseIf System.IsFunctionAvailable("sodium_sub", sodium) Then
		    sodium_sub(output, Nonce2, Max(output.Size, Nonce2.Size))
		  Else
		    Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		  End If
		  Return output
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function CompareNonce(Nonce1 As MemoryBlock, Nonce2 As MemoryBlock) As Int32
		  ' Compares Nonce1 to Nonce2 in constant time. Returns 0 if they are equal, +1 if Nonce1
		  ' is greater, or -1 if Nonce2 is greater.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.CompareNonce
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If Nonce1.Size < 0 Or Nonce2.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED)
		  Return sodium_compare(Nonce1, Nonce2, Max(Nonce1.Size, Nonce2.Size))
		End Function
	#tag EndMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha256_final Lib sodium (State As Ptr, OutputBuffer As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha256_init Lib sodium (State As Ptr, Key As Ptr, KeySize As Int32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha256_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha256_statebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha256_update Lib sodium (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha512_final Lib sodium (State As Ptr, OutputBuffer As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha512_init Lib sodium (State As Ptr, Key As Ptr, KeySize As Int32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha512_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha512_statebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_auth_hmacsha512_update Lib sodium (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_bytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_bytes_max Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_bytes_min Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_final Lib sodium (State As Ptr, OutputBuffer As Ptr, OutputSize As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_init Lib sodium (State As Ptr, Key As Ptr, KeySize As UInt32, OutLength As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_keybytes_max Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_keybytes_min Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_statebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_generichash_update Lib sodium (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_bytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_final Lib sodium (State As Ptr, OutputBuffer As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_init Lib sodium (State As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_statebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha256_update Lib sodium (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_bytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_final Lib sodium (State As Ptr, OutputBuffer As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_init Lib sodium (State As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_statebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_hash_sha512_update Lib sodium (State As Ptr, InputBuffer As Ptr, InputSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash Lib sodium (OutBuffer As Ptr, OutSize As UInt64, Passwd As Ptr, PasswdSize As UInt64, SaltBuffer As Ptr, OpsLimit As UInt64, MemLimit As UInt32, Algorithm As Int32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_alg_argon2i13 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_alg_argon2id13 Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_alg_default Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_memlimit_interactive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_memlimit_max Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_memlimit_min Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_memlimit_moderate Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_memlimit_sensitive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_opslimit_interactive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_opslimit_max Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_opslimit_min Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_opslimit_moderate Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_opslimit_sensitive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_argon2i_str Lib sodium (Buffer As Ptr, Passwd As Ptr, PasswdSize As UInt64, OpsLimit As UInt64, MemLimit As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_saltbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256 Lib sodium (OutBuffer As Ptr, OutSize As UInt64, Passwd As Ptr, PasswdSize As UInt64, SaltBuffer As Ptr, OpsLimit As UInt64, MemLimit As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_memlimit_interactive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_memlimit_max Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_memlimit_min Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_memlimit_moderate Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_opslimit_interactive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_opslimit_max Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_opslimit_min Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_opslimit_moderate Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_saltbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_str Lib sodium (Buffer As Ptr, Passwd As Ptr, PasswdSize As UInt64, OpsLimit As UInt64, MemLimit As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_strbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_scryptsalsa208sha256_str_verify Lib sodium (Hash As Ptr, Passwd As Ptr, PasswdSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_str Lib sodium (Buffer As Ptr, Passwd As Ptr, PasswdSize As UInt64, OpsLimit As UInt64, MemLimit As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_strbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_pwhash_str_verify Lib sodium (Hash As Ptr, Passwd As Ptr, PasswdSize As UInt64) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_shorthash Lib sodium (Buffer As Ptr, InputData As Ptr, InputDataSize As UInt64, Key As Ptr) As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_shorthash_bytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_shorthash_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream Lib sodium (OutBuffer As Ptr, OutSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_chacha20 Lib sodium (OutBuffer As Ptr, OutSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_chacha20_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_chacha20_noncebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_chacha20_xor Lib sodium (OutBuffer As Ptr, Message As Ptr, MsgSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub crypto_stream_keygen Lib sodium (Buffer As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_noncebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_salsa20 Lib sodium (OutBuffer As Ptr, OutSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_salsa20_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub crypto_stream_salsa20_keygen Lib sodium (Buffer As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_salsa20_noncebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_salsa20_xor Lib sodium (OutBuffer As Ptr, Message As Ptr, MsgSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_xchacha20 Lib sodium (OutBuffer As Ptr, OutSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_xchacha20_keybytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub crypto_stream_xchacha20_keygen Lib sodium (Buffer As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_xchacha20_noncebytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_xchacha20_xor Lib sodium (OutBuffer As Ptr, Message As Ptr, MsgSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_stream_xor Lib sodium (OutBuffer As Ptr, Message As Ptr, MsgSize As UInt64, Nonce As Ptr, KeyStream As Ptr) As Int32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function DecodeBase64(Data As MemoryBlock, IgnoredChars As String = "", Type As libsodium.Base64Variant = libsodium.Base64Variant.Original) As MemoryBlock
		  ' Decodes base64 to binary. On error, returns Nil. IgnoredChars is an optional string
		  ' of characters to skip when interpreting the Data
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.DecodeBase64
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Data = ReplaceLineEndings(Data, "")
		  Dim output As New MemoryBlock(Data.Size)
		  Dim end64 As Ptr
		  Dim ign As MemoryBlock = IgnoredChars + Chr(0)
		  Dim sz As UInt32 = output.Size
		  If sodium_base642bin(output, output.Size, Data, Data.Size, ign, sz, end64, Type) = 0 Then
		    Return output.StringValue(0, sz)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function DecodeHex(HexData As MemoryBlock, IgnoredChars As String = "") As MemoryBlock
		  ' Decodes hexadecimal to binary. On error, returns Nil. IgnoredChars is an optional
		  ' string of characters to skip when interpreting the HexData
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.DecodeHex
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim output As New MemoryBlock(HexData.Size)
		  Dim endhex As Ptr
		  Dim ign As MemoryBlock = IgnoredChars + Chr(0)
		  Dim sz As UInt32 = output.Size
		  If sodium_hex2bin(output, output.Size, HexData, HexData.Size, ign, sz, endhex) = 0 Then
		    Return output.StringValue(0, sz)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncodeBase64(BinaryData As MemoryBlock, Type As libsodium.Base64Variant = libsodium.Base64Variant.Original) As MemoryBlock
		  ' Encodes the BinaryData as Base64
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.EncodeBase64
		  
		  If Not IsAvailable() Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim output As New MemoryBlock(sodium_base64_encoded_len(BinaryData.Size, Type))
		  If sodium_bin2base64(output, output.Size, BinaryData, BinaryData.Size, Type) <> Nil Then Return output.CString(0)
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function EncodeHex(BinaryData As MemoryBlock, ToUppercase As Boolean = True) As MemoryBlock
		  ' Encodes the BinaryData as ASCII hexadecimal
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.EncodeHex
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim output As New MemoryBlock(BinaryData.Size * 2 + 1)
		  If sodium_bin2hex(output, output.Size, BinaryData, BinaryData.Size) <> Nil Then
		    If ToUppercase Then
		      Return output.CString(0).Uppercase
		    Else
		      Return output.CString(0)
		    End If
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function GenericHash(InputData As MemoryBlock, Key As MemoryBlock = Nil, Optional HashSize As UInt32) As String
		  ' Generates a 512-bit BLAKE2b digest of the InputData, optionally using the specified key.
		  ' https://download.libsodium.org/doc/hashing/generic_hashing.html
		  
		  If HashSize = 0 Then HashSize = crypto_generichash_bytes_max()
		  Dim h As New GenericHashDigest(HashSize, Key)
		  h.Process(InputData)
		  Return h.Value
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function get_errno() As Integer
		  Dim err As Integer
		  Dim mb As MemoryBlock
		  #If TargetWin32 Then
		    Declare Function _get_errno Lib "msvcrt" (ByRef Error As Integer) As Integer
		    Dim e As Integer = _get_errno(err)
		    If e <> 0 Then err = e
		  #elseif TargetLinux
		    Declare Function __errno_location Lib "libc.so" () As Ptr
		    mb = __errno_location()
		  #elseif TargetMacOS
		    Declare Function __error Lib "System" () As Ptr
		    mb = __error()
		  #endif
		  If mb <> Nil Then err = mb.Int32Value(0)
		  Return err
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function IncrementNonce(Nonce As MemoryBlock) As MemoryBlock
		  ' Increments the Nonce in constant time.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.IncrementNonce
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Dim output As New MemoryBlock(Nonce.Size)
		  output.StringValue(0, output.Size) = Nonce.StringValue(0, Nonce.Size)
		  sodium_increment(output, output.Size)
		  Return output
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function IsAvailable() As Boolean
		  ' Returns True if libsodium is available.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.IsAvailable
		  
		  Static available As Boolean
		  
		  If Not available Then available = System.IsFunctionAvailable("sodium_init", sodium)
		  If available Then
		    If sodium_init() = -1 Then available = False Else available = True
		  End If
		  Return available
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function IsZero(Extends mb As MemoryBlock, Offset As Int32 = 0, Length As Int32 = - 1) As Boolean
		  ' This method returns True if the MemoryBlock contains only zeros. It returns False
		  ' if non-zero bits are found. Execution time is constant for a given length.
		  
		  If mb = Nil Then Return True
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If Offset < 0 Or mb.Size < 0 Then Raise New SodiumException(ERR_OUT_OF_RANGE)
		  Dim p As Ptr = mb
		  If Length < 0 Then Length = mb.Size
		  If Offset + Length > mb.Size Then Raise New SodiumException(ERR_OUT_OF_RANGE)
		  If Offset > 0 Then
		    p = Ptr(Integer(p) + Offset)
		  Else
		    p = mb
		  End If
		  
		  Return sodium_is_zero(p, Length) = 1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub PadData(ByRef Data As MemoryBlock, BlockSize As UInt32)
		  ' Adds padding to the Data, using the ISO/IEC 7816-4 padding algorithm, until the Data.Size
		  ' is a multiple of the BlockSize. Use UnpadData to remove the padding.
		  
		  If Not IsAvailable() Or Not System.IsFunctionAvailable("sodium_pad", sodium) Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If Data.Size = -1 Then Raise New SodiumException(ERR_SIZE_REQUIRED)
		  Dim origsz As UInt32 = Data.Size
		  Dim padsz As UInt32
		  Data.Size = ((Data.Size \ BlockSize) * BlockSize) + BlockSize
		  If sodium_pad(padsz, Data, origsz, BlockSize, Data.Size) <> 0 Then Raise New SodiumException(ERR_PADDING)
		  If Data.Size <> padsz Then
		    Break ' this should never happen
		    Data.Size = padsz
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function RandomBytes(Count As UInt32, Optional Seed As MemoryBlock) As MemoryBlock
		  ' Returns a MemoryBlock filled with the requested number of unpredictable bytes.
		  '   On Win32, the RtlGenRandom() function is used
		  '   On BSD, the arc4random() function is used
		  '   On recent Linux kernels, the getrandom system call is used (since Sodium 1.0.3)
		  '   On other Unices, the /dev/urandom device is used
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.RandomBytes
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim mb As New MemoryBlock(Count)
		  If Seed = Nil Then
		    randombytes_buf(mb, mb.Size)
		  Else
		    If Not System.IsFunctionAvailable("randombytes_buf_deterministic", sodium) Then Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		    CheckSize(Seed, randombytes_seedbytes)
		    randombytes_buf_deterministic(mb, mb.Size, Seed)
		  End If
		  Return mb
		End Function
	#tag EndMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub randombytes_buf Lib sodium (Buffer As Ptr, BufferSize As UInt32)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub randombytes_buf_deterministic Lib sodium (Buffer As Ptr, BufferSize As UInt32, SeedData As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function randombytes_random Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function randombytes_seedbytes Lib sodium () As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function randombytes_uniform Lib sodium (UpperBound As UInt32) As UInt32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function RandomUInt32(Optional UpperBound As UInt32) As UInt32
		  ' Returns an unpredictable UInt32 between 0 and &hffffffff. If UpperBound is specified
		  ' then the value will be less-than UpperBound.
		  ' https://download.libsodium.org/doc/generating_random_data/
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If UpperBound = 0 Then
		    Return randombytes_random()
		  Else
		    Return randombytes_uniform(UpperBound)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function Scrypt(InputData As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive) As String
		  ' Generates a scrypt digest of the InputData
		  ' https://download.libsodium.org/doc/password_hashing/scrypt.html
		  
		  Dim p As New libsodium.Password(InputData)
		  Return p.GenerateHash(Password.ALG_SCRYPT, Limits)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function ScryptVerify(InputData As MemoryBlock, HashValue As MemoryBlock) As Boolean
		  ' Verifies an scrypt digest of the InputData
		  ' https://download.libsodium.org/doc/password_hashing/scrypt.html
		  
		  Dim p As New libsodium.Password(InputData)
		  Return p.VerifyHash(HashValue, Password.ALG_SCRYPT)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SHA256(InputData As MemoryBlock, HMACKey As MemoryBlock = Nil) As String
		  ' Generates a SHA256 digest of the InputData
		  ' https://download.libsodium.org/doc/advanced/sha-2_hash_function.html
		  
		  Dim h As New GenericHashDigest(HashType.SHA256, HMACKey)
		  h.Process(InputData)
		  Return h.Value
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function SHA512(InputData As MemoryBlock, HMACKey As MemoryBlock = Nil) As String
		  ' Generates a SHA512 digest of the InputData
		  ' https://download.libsodium.org/doc/advanced/sha-2_hash_function.html
		  
		  Dim h As New GenericHashDigest(HashType.SHA512, HMACKey)
		  h.Process(InputData)
		  Return h.Value
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function ShortHash(InputData As MemoryBlock, Key As MemoryBlock) As UInt64
		  ' Generates a 64-bit (8-byte) hash of the InputData using the specified key. The
		  ' output is a short but unpredictable (without knowing the secret key) value 
		  ' suitable for picking a list in a hash table for a given key. The Key must be 
		  ' exactly 16 bytes in size. This hash function should not be considered to be
		  ' collision resistant.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/hashing/short-input_hashing.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.ShortHash
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(Key, crypto_shorthash_keybytes)
		  
		  Dim buffer As New MemoryBlock(crypto_shorthash_bytes)
		  If crypto_shorthash(buffer, InputData, InputData.Size, Key) = 0 Then
		    Return buffer.UInt64Value(0)
		  End If
		End Function
	#tag EndMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_add Lib sodium (BufferA As Ptr, BufferB As Ptr, Length As UInt32)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_allocarray Lib sodium (Count As UInt32, FieldSize As UInt32) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_base642bin Lib sodium (BinBuffer As Ptr, BinBufferMaxLength As UInt32, Output As Ptr, OutputLength As UInt32, IgnoreChars As Ptr, ByRef BinBufferLength As UInt32, ByRef OutputEnd As Ptr, Flag As Base64Variant) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_base64_encoded_len Lib sodium (BinLength As UInt32, Type As Base64Variant) As UInt32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_bin2base64 Lib sodium (Output As Ptr, MaxLength As UInt32, Buffer As Ptr, BufferLength As UInt32, Flag As Base64Variant) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_bin2hex Lib sodium (HexBuffer As Ptr, HexBufferLength As UInt32, BinBuffer As Ptr, BinBufferLength As UInt32) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_compare Lib sodium (Buffer1 As Ptr, Buffer2 As Ptr, Length As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_free Lib sodium (DataPtr As Ptr)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_hex2bin Lib sodium (BinBuffer As Ptr, BinBufferMaxLength As UInt32, HexBuffer As Ptr, HexBufferLength As UInt32, IgnoreChars As Ptr, ByRef BinBufferLength As UInt32, ByRef HexEnd As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_increment Lib sodium (Number As Ptr, Length As UInt32)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_init Lib sodium () As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_is_zero Lib sodium (DataPtr As Ptr, Length As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_malloc Lib sodium (Length As UInt32) As Ptr
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_memcmp Lib sodium (Buffer1 As Ptr, Buffer2 As Ptr, Length As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_memzero Lib sodium (DataPtr As Ptr, Length As UInt32)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mlock Lib sodium (Address As Ptr, Length As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mprotect_noaccess Lib sodium (DataPtr As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mprotect_readonly Lib sodium (DataPtr As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_mprotect_readwrite Lib sodium (DataPtr As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_munlock Lib sodium (Address As Ptr, Length As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_pad Lib sodium (ByRef BufferSize As UInt32, Buffer As Ptr, UnpaddedSize As UInt32, BlockSize As UInt32, MaxBufferSize As UInt32) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Sub sodium_sub Lib sodium (BufferA As Ptr, BufferB As Ptr, Length As UInt32)
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function sodium_unpad Lib sodium (ByRef BufferSize As UInt32, Buffer As Ptr, UnpaddedSize As UInt32, BlockSize As UInt32) As Int32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function StrComp(String1 As String, String2 As String) As Boolean
		  ' Performs a constant-time binary comparison of the strings, and returns True if they are identical.
		  ' https://download.libsodium.org/doc/helpers/#constant-time-test-for-equality
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Dim mb1 As MemoryBlock = String1
		  Dim mb2 As MemoryBlock = String2
		  Dim sz As UInt32
		  If mb1.Size <> mb2.Size Then
		    sz = Max(mb1.Size, mb2.Size)
		    ' pad the smaller string with zeroes to preserve constant time
		    If mb1.Size <> sz Then mb1.Size = sz Else mb2.Size = sz
		  Else
		    sz = mb1.Size
		  End If
		  
		  Return sodium_memcmp(mb1, mb2, sz) = 0
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub UnpadData(ByRef Data As MemoryBlock, BlockSize As UInt32)
		  ' Removes the padding that was applied to the Data by the PadData method.
		  
		  If Not IsAvailable() Or Not System.IsFunctionAvailable("sodium_unpad", sodium) Then Raise New SodiumException(ERR_UNAVAILABLE)
		  If Data.Size = -1 Then Raise New SodiumException(ERR_SIZE_REQUIRED)
		  Dim unpadsz As UInt32
		  If sodium_unpad(unpadsz, Data, Data.Size, BlockSize) <> 0 Then Raise New SodiumException(ERR_PADDING)
		  Data.Size = unpadsz
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub ZeroFill(Extends mb As MemoryBlock, Offset As Int32 = 0, Length As Int32 = -1)
		  ' Overwrites the data in the MemoryBlock with zeroes.
		  
		  If mb = Nil Then Return
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Dim p As Ptr = mb
		  If Length < 0 Then Length = mb.Size
		  CheckSize(Offset, 0, mb.Size)
		  CheckSize(Length, 0, mb.Size - Offset)
		  CheckSize(Offset + Length, 0, mb.Size)
		  If Offset > 0 Then p = Ptr(Integer(p) + Offset)
		  
		  sodium_memzero(p, Length)
		End Sub
	#tag EndMethod


	#tag Constant, Name = ERR_CANT_ALLOC, Type = Double, Dynamic = False, Default = \"-5", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_COMPUTATION_FAILED, Type = Double, Dynamic = False, Default = \"-12", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_CONVERSION_FAILED, Type = Double, Dynamic = False, Default = \"-18", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_DECRYPT_FAIL, Type = Double, Dynamic = False, Default = \"-28", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_FUNCTION_UNAVAILABLE, Type = Double, Dynamic = False, Default = \"-23", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_IMPORT_ENCRYPTED, Type = Double, Dynamic = False, Default = \"-20", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_IMPORT_INVALID, Type = Double, Dynamic = False, Default = \"-26", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_IMPORT_PASSWORD, Type = Double, Dynamic = False, Default = \"-19", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_INIT_FAILED, Type = Double, Dynamic = False, Default = \"-2", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_INVALID_STATE, Type = Double, Dynamic = False, Default = \"-11", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_KEYDERIVE_FAILED, Type = Double, Dynamic = False, Default = \"-15", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_KEYGEN_FAILED, Type = Double, Dynamic = False, Default = \"-14", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_KEYTYPE_MISMATCH, Type = Double, Dynamic = False, Default = \"-24", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_LOCK_DENIED, Type = Double, Dynamic = False, Default = \"-9", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_OPSLIMIT, Type = Double, Dynamic = False, Default = \"-16", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_OUT_OF_BOUNDS, Type = Double, Dynamic = False, Default = \"-10", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_OUT_OF_RANGE, Type = Double, Dynamic = False, Default = \"-17", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_PADDING, Type = Double, Dynamic = False, Default = \"-27", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_PARAMETER_CONFLICT, Type = Double, Dynamic = False, Default = \"-25", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_PROTECT_FAILED, Type = Double, Dynamic = False, Default = \"-4", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_READ_DENIED, Type = Double, Dynamic = False, Default = \"-7", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_SIZE_MISMATCH, Type = Double, Dynamic = False, Default = \"-13", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_SIZE_REQUIRED, Type = Double, Dynamic = False, Default = \"-22", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_TOO_LARGE, Type = Double, Dynamic = False, Default = \"-6", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_UNAVAILABLE, Type = Double, Dynamic = False, Default = \"-3", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_UNSUITABLE, Type = Double, Dynamic = False, Default = \"-29", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_WRITE_DENIED, Type = Double, Dynamic = False, Default = \"-8", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = ERR_WRONG_HALF, Type = Double, Dynamic = False, Default = \"-21", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = sodium, Type = String, Dynamic = False, Default = \"libsodium.so", Scope = Private
		#Tag Instance, Platform = Linux, Language = Default, Definition  = \"libsodium.so"
		#Tag Instance, Platform = Mac OS, Language = Default, Definition  = \"libsodium.dylib"
		#Tag Instance, Platform = Windows, Language = Default, Definition  = \"libsodium.dll"
	#tag EndConstant


	#tag Enum, Name = Base64Variant, Type = Integer, Flags = &h1
		Original=1
		  NoPadding=3
		  URLSafe=5
		URLSafeNoPadding=7
	#tag EndEnum

	#tag Enum, Name = ExportableType, Flags = &h1
		CryptPrivate
		  CryptPublic
		  SignPrivate
		  SignPublic
		  Secret
		  SharedSecret
		  Unknown
		  Signature
		  HMAC
		  StateHeader
		SignatureDigest
	#tag EndEnum

	#tag Enum, Name = HashType, Type = Integer, Flags = &h1
		Generic
		  SHA256
		SHA512
	#tag EndEnum

	#tag Enum, Name = ProtectionLevel, Flags = &h1
		ReadWrite
		  ReadOnly
		NoAccess
	#tag EndEnum

	#tag Enum, Name = ResourceLimits, Type = Integer, Flags = &h1
		Sensitive
		  Moderate
		Interactive
	#tag EndEnum

	#tag Enum, Name = StreamType, Type = Integer, Flags = &h1
		ChaCha20
		  XChaCha20
		  Salsa20
		XSalsa20
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
