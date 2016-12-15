#tag Class
Protected Class Password
Implements libsodium.Secureable
	#tag Method, Flags = &h0
		Sub Constructor(Passwd As String)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  mSessionKey = libsodium.SKI.RandomKey
		  
		  If SessionNonce = Nil Then SessionNonce = libsodium.SKI.RandomNonce
		  Passwd = libsodium.SKI.EncryptData(Passwd, mSessionKey, SessionNonce)
		  mPassword = New SecureMemoryBlock(Passwd.LenB)
		  mPassword.StringValue(0, mPassword.Size) = Passwd
		  mPassword.AllowSwap = False
		  Me.Lock()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveKey(KeyLength As Int32, Salt As MemoryBlock, Limits As libsodium.ResourceLimits, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2) As MemoryBlock
		  Dim out As New MemoryBlock(KeyLength)
		  Dim clearpw As MemoryBlock = Me.Value
		  Dim memlimit, opslimit As UInt32
		  GetLimits(HashAlgorithm, Limits, memlimit, opslimit)
		  
		  Select Case HashAlgorithm
		  Case ALG_ARGON2
		    If Salt.Size <> crypto_pwhash_SALTBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    If crypto_pwhash(out, out.Size, clearpw, clearpw.Size, Salt, opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) = -1 Then
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		    
		  Case ALG_SCRYPT
		    If Salt.Size <> crypto_pwhash_scryptsalsa208sha256_SALTBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    If crypto_pwhash_scryptsalsa208sha256(out, out.Size, clearpw, clearpw.Size, Salt, opslimit, memlimit) = -1 Then 
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		    
		  End Select
		  
		  Return out
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  mPassword = Nil
		End Sub
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
		    If crypto_pwhash_str(out, clearpw, clearpw.Size, OpsLimit, MemLimit) = -1 Then
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
		      Memlimit = MEMLIMIT_INTERACTIVE
		      OpsLimit = OPSLIMIT_INTERACTIVE
		    Case libsodium.ResourceLimits.Moderate
		      Memlimit = MEMLIMIT_MODERATE
		      OpsLimit = OPSLIMIT_MODERATE
		    Case libsodium.ResourceLimits.Sensitive
		      Memlimit = MEMLIMIT_SENSITIVE
		      OpsLimit = OPSLIMIT_SENSITIVE
		    End Select
		  Else
		    If Limits = libsodium.ResourceLimits.Interactive Then
		      Memlimit = scrypt_MEMLIMIT_INTERACTIVE
		      OpsLimit = scrypt_OPSLIMIT_INTERACTIVE
		    Else
		      Memlimit = scrypt_MEMLIMIT_SENSITIVE
		      OpsLimit = scrypt_OPSLIMIT_SENSITIVE
		    End If
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  mPassword.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherPassword As libsodium.Password) As Int32
		  If OtherPassword Is Nil Then Return 1
		  If libsodium.StrComp(Me.Value, OtherPassword.Value) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherPassword As String) As Int32
		  If libsodium.StrComp(Me.Value, OtherPassword) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromString As String)
		  Me.Constructor(FromString)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  mPassword.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As libsodium.SecureMemoryBlock
		  Dim ret As New SecureMemoryBlock(mPassword.Size)
		  Me.Unlock()
		  Try
		    ret = libsodium.SKI.DecryptData(mPassword.StringValue(0, mPassword.Size), mSessionKey, SessionNonce)
		  Finally
		    Me.Lock()
		  End Try
		  Return ret
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function VerifyHash(HashValue As MemoryBlock, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2) As Boolean
		  Dim clearpw As SecureMemoryBlock = Me.Value
		  Select Case HashAlgorithm
		  Case ALG_ARGON2
		    Select Case HashValue.Size
		    Case Is < crypto_pwhash_STRBYTES
		      HashValue.Size = crypto_pwhash_STRBYTES
		    Case Is > crypto_pwhash_STRBYTES
		      Raise New SodiumException(ERR_SIZE_MISMATCH)
		    End Select
		    Return crypto_pwhash_str_verify(HashValue, clearpw.TruePtr, clearpw.Size) = 0
		    
		  Case ALG_SCRYPT
		    If HashValue.Size <> crypto_pwhash_scryptsalsa208sha256_STRBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    Return crypto_pwhash_scryptsalsa208sha256_str_verify(HashValue, clearpw.TruePtr, clearpw.Size) = 0
		  End Select
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mPassword As libsodium.SecureMemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mSessionKey As libsodium.SKI.SecretKey
	#tag EndProperty

	#tag Property, Flags = &h21
		Private Shared SessionNonce As MemoryBlock
	#tag EndProperty


	#tag Constant, Name = ALG_ARGON2, Type = Double, Dynamic = False, Default = \"0", Scope = Public
	#tag EndConstant

	#tag Constant, Name = ALG_SCRYPT, Type = Double, Dynamic = False, Default = \"1", Scope = Public
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_ALG_DEFAULT, Type = Double, Dynamic = False, Default = \"1", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_scryptsalsa208sha256_SALTBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_scryptsalsa208sha256_STRBYTES, Type = Double, Dynamic = False, Default = \"102", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"33554432", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_MODERATE, Type = Double, Dynamic = False, Default = \"134217728", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"536870912", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"4", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_MODERATE, Type = Double, Dynamic = False, Default = \"6", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"8", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = Scrypt_MEMLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"16777216", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = Scrypt_MEMLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"1073741824", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = Scrypt_OPSLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"524288", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = Scrypt_OPSLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"33554432", Scope = Protected
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
