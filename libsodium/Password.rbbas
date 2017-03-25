#tag Class
Protected Class Password
Inherits libsodium.SKI.KeyContainer
	#tag Method, Flags = &h0
		Function DeriveKey(KeyLength As Int32, Salt As MemoryBlock, Limits As libsodium.ResourceLimits, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2) As MemoryBlock
		  ' Computes a key of the specified KeySize using the password, Salt, and other parameters.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html#key-derivation
		  ' https://download.libsodium.org/doc/password_hashing/scrypt.html#key-derivation
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.Password.DeriveKey
		  
		  Dim out As New MemoryBlock(KeyLength)
		  Dim clearpw As MemoryBlock = Me.Value
		  Dim memlimit, opslimit As UInt32
		  GetLimits(HashAlgorithm, Limits, memlimit, opslimit)
		  
		  Select Case HashAlgorithm
		  Case ALG_ARGON2
		    CheckSize(Salt, crypto_pwhash_SALTBYTES)
		    If crypto_pwhash(out, out.Size, clearpw, clearpw.Size, Salt, opslimit, memlimit, 1) = -1 Then ' Fixme: use crypto_pwhash_alg_default
		      HashAlgorithm = get_errno
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		    
		  Case ALG_SCRYPT
		    CheckSize(Salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
		    If crypto_pwhash_scryptsalsa208sha256(out, out.Size, clearpw, clearpw.Size, Salt, opslimit, memlimit) = -1 Then
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		    
		  End Select
		  
		  Return out
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function GenerateHash(HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive) As MemoryBlock
		  Dim out As MemoryBlock
		  Dim clearpw As MemoryBlock = Me.Value
		  Dim memlimit, opslimit As UInt32
		  GetLimits(HashAlgorithm, Limits, memlimit, opslimit)
		  
		  Select Case HashAlgorithm
		  Case ALG_ARGON2
		    out = New MemoryBlock(crypto_pwhash_STRBYTES)
		    If crypto_pwhash_argon2i_str(out, clearpw, clearpw.Size, OpsLimit, MemLimit) = -1 Then
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		  Case ALG_SCRYPT
		    out = New MemoryBlock(crypto_pwhash_scryptsalsa208sha256_STRBYTES)
		    If crypto_pwhash_scryptsalsa208sha256_str(out, clearpw, clearpw.Size, OpsLimit, MemLimit) = -1 Then
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		  End Select
		  
		  Return out.CString(0)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub GetLimits(Algorithm As Int32, Limits As libsodium.ResourceLimits, ByRef Memlimit As UInt32, ByRef OpsLimit As UInt32)
		  If Algorithm = ALG_ARGON2 Then
		    Select Case Limits
		    Case libsodium.ResourceLimits.Interactive
		      Memlimit = crypto_pwhash_argon2i_memlimit_interactive()
		      OpsLimit = crypto_pwhash_argon2i_opslimit_interactive()
		    Case libsodium.ResourceLimits.Moderate
		      Memlimit = crypto_pwhash_argon2i_memlimit_moderate()
		      OpsLimit = crypto_pwhash_argon2i_opslimit_moderate()
		    Case libsodium.ResourceLimits.Sensitive
		      Memlimit = crypto_pwhash_argon2i_memlimit_sensitive()
		      OpsLimit = crypto_pwhash_argon2i_opslimit_sensitive()
		    End Select
		  Else
		    If Limits = libsodium.ResourceLimits.Interactive Then
		      Memlimit = crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()
		      OpsLimit = crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()
		    Else
		      Memlimit = crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()
		      OpsLimit = crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
		    End If
		  End If
		  
		  'If System.IsFunctionAvailable("crypto_pwhash_argon2i_opslimit_max", "libsodium") Then
		  'If Algorithm = ALG_ARGON2 Then
		  'CheckSize(Memlimit, crypto_pwhash_argon2i_memlimit_min(), crypto_pwhash_argon2i_memlimit_max())
		  'CheckSize(OpsLimit, crypto_pwhash_argon2i_opslimit_min(), crypto_pwhash_argon2i_opslimit_max())
		  'Else
		  'CheckSize(Memlimit, crypto_pwhash_scryptsalsa208sha256_memlimit_min(), crypto_pwhash_scryptsalsa208sha256_memlimit_max())
		  'CheckSize(OpsLimit, crypto_pwhash_scryptsalsa208sha256_opslimit_min(), crypto_pwhash_scryptsalsa208sha256_opslimit_max())
		  'End If
		  'End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherPassword As libsodium.Password) As Int32
		  If OtherPassword Is Nil Then Return 1
		  Return Super.Operator_Compare(OtherPassword.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromString As String)
		  Me.Constructor(FromString)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomSalt(HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2) As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a salt for Password.DeriveKey
		  
		  If HashAlgorithm = ALG_ARGON2 Then
		    Return RandomBytes(crypto_pwhash_SALTBYTES)
		  Else
		    Return RandomBytes(crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function VerifyHash(HashValue As MemoryBlock, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2) As Boolean
		  ' This method verifies that the HashValue is a valid hash for the password (as generated
		  ' by Password.GenerateHash)
		  
		  Dim clearpw As MemoryBlock = Me.Value
		  Select Case HashAlgorithm
		  Case ALG_ARGON2
		    If HashValue.Size <= crypto_pwhash_STRBYTES Then HashValue.Size = crypto_pwhash_STRBYTES Else CheckSize(HashValue, crypto_pwhash_STRBYTES)
		    Return crypto_pwhash_str_verify(HashValue, clearpw, clearpw.Size) = 0
		    
		  Case ALG_SCRYPT
		    HashValue = HashValue + Chr(0)
		    CheckSize(HashValue, crypto_pwhash_scryptsalsa208sha256_STRBYTES)
		    Return crypto_pwhash_scryptsalsa208sha256_str_verify(HashValue, clearpw, clearpw.Size) = 0
		  End Select
		  
		End Function
	#tag EndMethod


	#tag Constant, Name = ALG_ARGON2, Type = Double, Dynamic = False, Default = \"0", Scope = Public
	#tag EndConstant

	#tag Constant, Name = ALG_SCRYPT, Type = Double, Dynamic = False, Default = \"1", Scope = Public
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_ALG_DEFAULT, Type = Double, Dynamic = False, Default = \"ALG_ARGON2", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_SALTBYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_scryptsalsa208sha256_SALTBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_scryptsalsa208sha256_STRBYTES, Type = Double, Dynamic = False, Default = \"102", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_STRBYTES, Type = Double, Dynamic = False, Default = \"128", Scope = Protected
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
End Class
#tag EndClass
