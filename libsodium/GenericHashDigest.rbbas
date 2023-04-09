#tag Class
Protected Class GenericHashDigest
	#tag Method, Flags = &h0
		Sub Constructor(Type As libsodium.HashType = libsodium.HashType.Generic, KeyData As MemoryBlock = Nil)
		  ' Instantiates the processor for hashing. If KeyData is specified then the hash is keyed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  mKey = KeyData
		  mType = Type
		  Select Case Type
		  Case HashType.Generic
		    If KeyData <> Nil Then CheckSize(KeyData, crypto_generichash_keybytes)
		    mHashSize = crypto_generichash_bytes_max
		    
		  Case HashType.SHA256
		    If KeyData <> Nil Then CheckSize(KeyData, crypto_auth_hmacsha256_keybytes)
		    mHashSize = crypto_hash_sha256_bytes
		    
		  Case HashType.SHA512
		    If KeyData <> Nil Then CheckSize(KeyData, crypto_auth_hmacsha512_keybytes)
		    mHashSize = crypto_hash_sha512_bytes
		    
		  End Select
		  
		  Me.Reset()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.Password, Salt As MemoryBlock, Type As libsodium.HashType = libsodium.HashType.Generic)
		  ' Instantiates the processor for hashing using a key derived from KeyData
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  Dim k As Int32
		  Select Case Type
		  Case HashType.Generic
		    k = crypto_generichash_keybytes
		  Case HashType.SHA256
		    k = crypto_auth_hmacsha256_keybytes
		  Case HashType.SHA512
		    k = crypto_auth_hmacsha512_keybytes
		  End Select
		  
		  Me.Constructor(Type, KeyData.DeriveKey(k, Salt, ResourceLimits.Interactive))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(HashSize As UInt32, KeyData As MemoryBlock)
		  ' Instantiates the processor for generic hashing.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  mType = HashType.Generic
		  If KeyData <> Nil Then CheckSize(KeyData, crypto_generichash_keybytes)
		  CheckSize(HashSize, crypto_generichash_bytes_min, crypto_generichash_bytes_max)
		  mKey = KeyData
		  mHashSize = HashSize
		  Me.Reset()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mOutput = Nil And mState <> Nil Then Call Me.Value
		  mState = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub FinalizeBlake2b()
		  mLastError = crypto_generichash_final(mState, mOutput, mOutput.Size)
		  mState = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub FinalizeSHA256()
		  If mKey = Nil Then
		    mLastError = crypto_hash_sha256_final(mState, mOutput)
		  Else
		    mLastError = crypto_auth_hmacsha256_final(mState, mOutput)
		  End If
		  mState = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub FinalizeSHA512()
		  If mKey = Nil Then
		    mLastError = crypto_hash_sha512_final(mState, mOutput)
		  Else
		    mLastError = crypto_auth_hmacsha512_final(mState, mOutput)
		  End If
		  mState = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub InitBlake2b()
		  mState = New MemoryBlock(crypto_generichash_statebytes())
		  
		  If mKey <> Nil Then
		    mLastError = crypto_generichash_init(mState, mKey, mKey.Size, mHashSize)
		  Else
		    mLastError = crypto_generichash_init(mState, Nil, 0, mHashSize)
		  End If
		  
		  mOutput = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub InitSHA256()
		  If mKey <> Nil Then
		    If Not System.IsFunctionAvailable("crypto_auth_hmacsha256_init", sodium) Then Raise New SodiumException(ERR_FUNCTION_UNAVAILABLE)
		    mState = New MemoryBlock(crypto_auth_hmacsha256_statebytes())
		    mLastError = crypto_auth_hmacsha256_init(mState, mKey, mKey.Size)
		  Else
		    mState = New MemoryBlock(crypto_hash_sha256_statebytes())
		    mLastError = crypto_hash_sha256_init(mState)
		  End If
		  
		  mOutput = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub InitSHA512()
		  If mKey <> Nil Then
		    If Not System.IsFunctionAvailable("crypto_auth_hmacsha512_init", sodium) Then Raise New SodiumException(ERR_UNAVAILABLE)
		    mState = New MemoryBlock(crypto_auth_hmacsha512_statebytes())
		    mLastError = crypto_auth_hmacsha512_init(mState, mKey, mKey.Size)
		  Else
		    mState = New MemoryBlock(crypto_hash_sha512_statebytes())
		    mLastError = crypto_hash_sha512_init(mState)
		  End If
		  
		  mOutput = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Process(NewData As MemoryBlock)
		  ' Processes the NewData into a running hash.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Process
		  
		  If mOutput <> Nil Then Raise New SodiumException(ERR_INVALID_STATE)
		  If NewData.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED) ' can't pass a MemoryBlock of unknown size
		  Select Case mType
		  Case HashType.Generic
		    ProcessBlake2b(NewData)
		  Case HashType.SHA256
		    ProcessSHA256(NewData)
		  Case HashType.SHA512
		    ProcessSHA512(NewData)
		  End Select
		  
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ProcessBlake2b(NewData As MemoryBlock)
		  mLastError = crypto_generichash_update(mState, NewData, NewData.Size)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ProcessSHA256(NewData As MemoryBlock)
		  If mKey = Nil Then
		    mLastError = crypto_hash_sha256_update(mState, NewData, NewData.Size)
		  Else
		    mLastError = crypto_auth_hmacsha256_update(mState, NewData, NewData.Size)
		  End If
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ProcessSHA512(NewData As MemoryBlock)
		  If mKey = Nil Then
		    mLastError = crypto_hash_sha512_update(mState, NewData, NewData.Size)
		  Else
		    mLastError = crypto_auth_hmacsha512_update(mState, NewData, NewData.Size)
		  End If
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomKey(Type As libsodium.HashType = libsodium.HashType.Generic) As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a key for GenericHashDigest.Constructor
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.RandomKey
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  
		  Select Case Type
		  Case HashType.Generic
		    Return RandomBytes(crypto_generichash_keybytes)
		    
		  Case HashType.SHA256
		    Return RandomBytes(crypto_auth_hmacsha256_keybytes)
		    
		  Case HashType.SHA512
		    Return RandomBytes(crypto_auth_hmacsha512_keybytes)
		    
		  End Select
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Reset()
		  ' Resets the processor state so that a new hash value can be computed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Reset
		  
		  Select Case mType
		  Case HashType.Generic
		    InitBlake2b()
		  Case HashType.SHA256
		    InitSHA256()
		  Case HashType.SHA512
		    InitSHA512()
		  End Select
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As String
		  ' Finalizes the digest operation and returns the hash value.
		  ' Once you call this method the processor can accept no more input until
		  ' the processor is Reset().
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Value
		  
		  If mOutput <> Nil Or mState = Nil Then Return mOutput
		  
		  mOutput = New MemoryBlock(mHashSize)
		  Select Case mType
		  Case HashType.Generic
		    FinalizeBlake2b()
		  Case HashType.SHA256
		    FinalizeSHA256()
		  Case HashType.SHA512
		    FinalizeSHA512()
		  End Select
		  
		  Return mOutput
		  
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mHashSize As UInt32
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mKey As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mLastError As Int32
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mOutput As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mState As MemoryBlock
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mType As libsodium.HashType
	#tag EndProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  ' The selected hash algorithm.
			  '
			  ' See:
			  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.GenericHashDigest.Type
			  
			  return mType
			End Get
		#tag EndGetter
		Type As libsodium.HashType
	#tag EndComputedProperty


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
