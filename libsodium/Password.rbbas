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
		Function DeriveKey(KeyLength As Int32, Salt As MemoryBlock, OpsLimit As Int32, MemLimit As Int32, HashAlgorithm As libsodium.Password.Algorithm = libsodium.Password.Algorithm.Argon2) As MemoryBlock
		  Dim out As New MemoryBlock(KeyLength)
		  Me.Unlock()
		  Dim clearpw As MemoryBlock
		  Try
		    clearpw = Me.Value
		  Finally
		    Me.Lock()
		  End Try
		  
		  Select Case HashAlgorithm
		  Case Algorithm.Argon2 
		    If crypto_pwhash( _
		      out, out.Size, _
		      clearpw, clearpw.Size, _
		      Salt, _
		      OpsLimit, _
		      MemLimit, _
		      crypto_pwhash_ALG_DEFAULT) = -1 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		      
		  Case Algorithm.Scrypt
		    If crypto_pwhash_scryptsalsa208sha256( _
		      out, out.Size, _
		      clearpw, clearpw.Size, _
		      Salt, _
		      OpsLimit, _
		      MemLimit) = -1 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		      
		  End Select
		  
		  Return out
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mPassword <> Nil Then mPassword.ZeroFill()
		  mPassword = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function GenerateHash(HashAlgorithm As libsodium.Password.Algorithm = libsodium.Password.Algorithm.Argon2, OpsLimit As Int32 = libsodium.Password.OPSLIMIT_INTERACTIVE, MemLimit As Int32 = libsodium.Password.MEMLIMIT_INTERACTIVE) As MemoryBlock
		  If OpsLimit < 3 Then Raise New SodiumException(ERR_OPSLIMIT)
		  Dim out As MemoryBlock
		  Dim clearpw As MemoryBlock
		  Me.Unlock()
		  Try
		    clearpw = Me.Value
		  Finally
		    Me.Lock()
		  End Try
		  
		  Select Case HashAlgorithm 
		  Case Algorithm.Argon2
		    out = New MemoryBlock(crypto_pwhash_STRBYTES)
		    If crypto_pwhash_str(out, clearpw, clearpw.Size, OpsLimit, MemLimit) = -1 Then
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		  Case Algorithm.Scrypt
		    out = New MemoryBlock(crypto_pwhash_scryptsalsa208sha256_STRBYTES)
		    If crypto_pwhash_scryptsalsa208sha256_str(out, clearpw, clearpw.Size, OpsLimit, MemLimit) = -1 Then
		      Raise New SodiumException(ERR_COMPUTATION_FAILED)
		    End If
		  End Select
		  
		  Return out
		End Function
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
		Function Value() As String
		  Dim ret As New MemoryBlock(mPassword.Size)
		  Me.Unlock()
		  Try
		    ret.StringValue(0, ret.Size) = mPassword.StringValue(0, mPassword.Size)
		    ret = libsodium.SKI.DecryptData(ret, mSessionKey, SessionNonce)
		  Finally
		    Me.Lock()
		  End Try
		  Return ret
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function VerifyHash(HashValue As MemoryBlock, HashAlgorithm As libsodium.Password.Algorithm = libsodium.Password.Algorithm.Argon2) As Boolean
		  Dim clearpw As MemoryBlock
		  Me.Unlock()
		  Try
		    clearpw = Me.Value
		  Finally
		    Me.Lock()
		  End Try
		  
		  Select Case HashAlgorithm
		  Case Algorithm.Argon2
		    If HashValue.Size <> crypto_pwhash_STRBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    Return crypto_pwhash_str_verify(HashValue, clearpw, clearpw.Size) = 0
		    
		  Case Algorithm.Scrypt
		    If HashValue.Size <> crypto_pwhash_scryptsalsa208sha256_STRBYTES Then Raise New SodiumException(ERR_SIZE_MISMATCH)
		    Return crypto_pwhash_scryptsalsa208sha256_str_verify(HashValue, clearpw, clearpw.Size) = 0
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


	#tag Constant, Name = crypto_pwhash_ALG_DEFAULT, Type = Double, Dynamic = False, Default = \"1", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_scryptsalsa208sha256_SALTBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = crypto_pwhash_scryptsalsa208sha256_STRBYTES, Type = Double, Dynamic = False, Default = \"102", Scope = Protected
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"33554432", Scope = Public
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_MODERATE, Type = Double, Dynamic = False, Default = \"134217728", Scope = Public
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"536870912", Scope = Public
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"4", Scope = Public
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_MODERATE, Type = Double, Dynamic = False, Default = \"6", Scope = Public
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"8", Scope = Public
	#tag EndConstant

	#tag Constant, Name = Scrypt_MEMLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"16777216", Scope = Public
	#tag EndConstant

	#tag Constant, Name = Scrypt_MEMLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"1073741824", Scope = Public
	#tag EndConstant

	#tag Constant, Name = Scrypt_OPSLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"524288", Scope = Public
	#tag EndConstant

	#tag Constant, Name = Scrypt_OPSLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"33554432", Scope = Public
	#tag EndConstant


	#tag Enum, Name = Algorithm, Type = Integer, Flags = &h0
		Argon2
		Scrypt
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
End Class
#tag EndClass
