#tag Class
Protected Class KeyStream
	#tag Method, Flags = &h0
		Sub Constructor(Cipher As libsodium.KeyStream.CipherType = libsodium.KeyStream.CipherType.XSalsa20)
		  ' Generates a random key stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  mType = Cipher
		  Select Case mType
		  Case CipherType.ChaCha20
		    Me.Constructor(RandomBytes(crypto_stream_chacha20_KEYBYTES))
		    
		  Case CipherType.XChaCha20
		    Me.Constructor(RandomBytes(crypto_stream_xchacha20_KEYBYTES))
		    
		  Case CipherType.Salsa20
		    Me.Constructor(RandomBytes(crypto_stream_salsa20_KEYBYTES))
		    
		  Case CipherType.XSalsa20
		    Me.Constructor(RandomBytes(crypto_stream_xsalsa20_KEYBYTES))
		    
		  End Select
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(Cipher As libsodium.KeyStream.CipherType = libsodium.KeyStream.CipherType.XSalsa20, FromPassword As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' Generates a key stream by deriving it from a salted hash of the password. The operation is
		  ' deterministic, such that calling this method twice with the same Password, Salt, and Limits
		  ' parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  If Salt = Nil Then Salt = FromPassword.RandomSalt(HashAlgorithm)
		  mType = Cipher
		  Select Case mType
		  Case CipherType.ChaCha20
		    Me.Constructor(FromPassword.DeriveKey(crypto_stream_chacha20_KEYBYTES, Salt, Limits, HashAlgorithm))
		    
		  Case CipherType.XChaCha20
		    Me.Constructor(FromPassword.DeriveKey(crypto_stream_xchacha20_KEYBYTES, Salt, Limits, HashAlgorithm))
		    
		  Case CipherType.Salsa20
		    Me.Constructor(FromPassword.DeriveKey(crypto_stream_salsa20_KEYBYTES, Salt, Limits, HashAlgorithm))
		    
		  Case CipherType.XSalsa20
		    Me.Constructor(FromPassword.DeriveKey(crypto_stream_xsalsa20_KEYBYTES, Salt, Limits, HashAlgorithm))
		    
		  End Select
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.PKI.ForeignKey)
		  ' Uses the KeyData as the key for the key stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  Me.Constructor(KeyData.Value)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(KeyData As MemoryBlock)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(KeyData, crypto_stream_KEYBYTES)
		  mKey = New libsodium.SKI.KeyContainer(KeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveKey(Size As Int32, Optional Nonce As MemoryBlock) As MemoryBlock
		  ' Returns the requested number of bytes from the key stream. Suitable for generating
		  ' keys or other pseudo-random data.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/advanced/xsalsa20.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.DeriveKey
		  
		  If Nonce = Nil Then Nonce = Me.RandomNonce(mType)
		  Dim mb As New MemoryBlock(Size)
		  
		  Select Case mType
		  Case CipherType.ChaCha20
		    CheckSize(Nonce, crypto_stream_chacha20_NONCEBYTES)
		    If crypto_stream_chacha20(mb, mb.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		    
		  Case CipherType.XChaCha20
		    CheckSize(Nonce, crypto_stream_xchacha20_NONCEBYTES)
		    If crypto_stream_xchacha20(mb, mb.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		    
		  Case CipherType.Salsa20
		    CheckSize(Nonce, crypto_stream_salsa20_NONCEBYTES)
		    If crypto_stream_salsa20(mb, mb.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		    
		  Case CipherType.XSalsa20
		    CheckSize(Nonce, crypto_stream_xsalsa20_NONCEBYTES)
		    If crypto_stream(mb, mb.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		    
		  End Select
		  
		  Return mb
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Process(Data As MemoryBlock, Nonce As MemoryBlock) As MemoryBlock
		  ' Encrypts or decrypts the Data by XOR'ing it with the key stream.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/advanced/xsalsa20.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Process
		  
		  Dim output As New MemoryBlock(Data.Size)
		  
		  Select Case mType
		  Case CipherType.ChaCha20
		    CheckSize(Nonce, crypto_stream_chacha20_NONCEBYTES)
		    If crypto_stream_chacha20_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  Case CipherType.XChaCha20
		    CheckSize(Nonce, crypto_stream_xchacha20_NONCEBYTES)
		    If crypto_stream_xchacha20_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  Case CipherType.Salsa20
		    CheckSize(Nonce, crypto_stream_salsa20_NONCEBYTES)
		    If crypto_stream_salsa20_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  Case CipherType.XSalsa20
		    CheckSize(Nonce, crypto_stream_xsalsa20_NONCEBYTES)
		    If crypto_stream_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  End Select
		  
		  Return output
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce(Cipher As libsodium.KeyStream.CipherType = libsodium.KeyStream.CipherType.XSalsa20) As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a Nonce for use with KeyStream.Process
		  ' and KeyStream.DeriveKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.RandomNonce
		  
		  Select Case Cipher
		  Case CipherType.ChaCha20
		    Return RandomBytes(crypto_stream_chacha20_NONCEBYTES)
		    
		  Case CipherType.XChaCha20
		    Return RandomBytes(crypto_stream_xchacha20_NONCEBYTES)
		    
		  Case CipherType.Salsa20
		    Return RandomBytes(crypto_stream_salsa20_NONCEBYTES)
		    
		  Case CipherType.XSalsa20
		    Return RandomBytes(crypto_stream_xsalsa20_NONCEBYTES)
		    
		  End Select
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Type() As libsodium.KeyStream.CipherType
		  Return mType
		End Function
	#tag EndMethod


	#tag Note, Name = About key streams
		The Process method, viewed as a function of the nonce for a uniform random key, is designed to meet the standard notion
		of unpredictability ("PRF"). For a formal definition see, e.g., Section 2.3 of Bellare, Kilian, and Rogaway, "The security of the 
		cipher block chaining message authentication code," Journal of Computer and System Sciences 61 (2000), 362–399; 
		http://www-cse.ucsd.edu/~mihir/papers/cbc.html.
		
		This means that an attacker cannot distinguish this function from a uniform random function. Consequently, if a series of messages 
		is encrypted by the Process method with a different nonce for each message, the ciphertexts are indistinguishable from uniform random 
		strings of the same length.
		
		Note that the length is not hidden. Note also that it is the caller's responsibility to ensure the uniqueness of nonces—for example, 
		by using nonce 1 for the first message, nonce 2 for the second message, etc. Nonces are long enough that randomly generated nonces 
		have negligible risk of collision.
		
		libsodium does not make any promises regarding the resistance of the derived keys to "related-key attacks." It is the caller's 
		responsibility to use proper key-derivation functions; all of this class's public Constructor methods derive proper keys.
	#tag EndNote


	#tag Property, Flags = &h1
		Protected mKey As libsodium.SKI.KeyContainer
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mType As libsodium.KeyStream.CipherType
	#tag EndProperty


	#tag Constant, Name = crypto_stream_chacha20_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_chacha20_NONCEBYTES, Type = Double, Dynamic = False, Default = \"8", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_salsa20_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_salsa20_NONCEBYTES, Type = Double, Dynamic = False, Default = \"8", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_xchacha20_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_xchacha20_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_xsalsa20_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_xsalsa20_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
	#tag EndConstant


	#tag Enum, Name = CipherType, Type = Integer, Flags = &h0
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
End Class
#tag EndClass
