#tag Class
Protected Class KeyStream
	#tag Method, Flags = &h0
		Sub Constructor(FromPassword As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2, NewStreamType As libsodium.StreamType = libsodium.StreamType.XSalsa20)
		  ' Generates a key stream by deriving it from a salted hash of the password. The operation is
		  ' deterministic, such that calling this method twice with the same Password, Salt, and Limits
		  ' parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  Dim sz As Integer
		  Select Case mType
		  Case StreamType.ChaCha20
		    sz = crypto_stream_chacha20_keybytes
		  Case StreamType.XChaCha20
		    sz = crypto_stream_xchacha20_keybytes
		  Case StreamType.Salsa20
		    sz = crypto_stream_salsa20_keybytes
		  Case StreamType.XSalsa20
		    sz = crypto_stream_keybytes
		  End Select
		  If sz = 0 Then Raise New SodiumException(ERR_OUT_OF_RANGE)
		  
		  If Salt = Nil Then Salt = FromPassword.RandomSalt(HashAlgorithm)
		  mType = NewStreamType
		  Me.Constructor(FromPassword.DeriveKey(sz, Salt, Limits, HashAlgorithm))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(KeyData As libsodium.PKI.ForeignKey, NewStreamType As libsodium.StreamType = libsodium.StreamType.XSalsa20)
		  ' Uses the KeyData as the key for the key stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  mType = NewStreamType
		  Me.Constructor(KeyData.Value)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(NewStreamType As libsodium.StreamType = libsodium.StreamType.XSalsa20)
		  ' Generates a random key stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  Dim sz As Integer
		  Select Case NewStreamType
		  Case StreamType.ChaCha20
		    sz = crypto_stream_chacha20_keybytes
		  Case StreamType.XChaCha20
		    sz = crypto_stream_xchacha20_keybytes
		  Case StreamType.Salsa20
		    sz = crypto_stream_salsa20_keybytes
		  Case StreamType.XSalsa20
		    sz = crypto_stream_keybytes
		  End Select
		  
		  If sz = 0 Then Raise New SodiumException(ERR_OUT_OF_RANGE)
		  mType = NewStreamType
		  Me.Constructor(RandomBytes(sz))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Constructor(KeyData As MemoryBlock)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Select Case mType
		  Case StreamType.ChaCha20
		    CheckSize(KeyData, crypto_stream_chacha20_keybytes)
		  Case StreamType.XChaCha20
		    CheckSize(KeyData, crypto_stream_xchacha20_keybytes)
		  Case StreamType.Salsa20
		    CheckSize(KeyData, crypto_stream_salsa20_keybytes)
		  Case StreamType.XSalsa20
		    CheckSize(KeyData, crypto_stream_keybytes)
		  End Select
		  
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
		  Select Case Type
		  Case StreamType.ChaCha20
		    CheckSize(Nonce, crypto_stream_chacha20_noncebytes)
		    If crypto_stream_chacha20(mb, mb.Size, Nonce, mKey.Value) <> 0 Then mb = Nil
		    
		  Case StreamType.XChaCha20
		    CheckSize(Nonce, crypto_stream_xchacha20_noncebytes)
		    If crypto_stream_xchacha20(mb, mb.Size, Nonce, mKey.Value) <> 0 Then mb = Nil
		    
		  Case StreamType.Salsa20
		    CheckSize(Nonce, crypto_stream_salsa20_noncebytes)
		    If crypto_stream_salsa20(mb, mb.Size, Nonce, mKey.Value) <> 0 Then mb = Nil
		    
		  Case StreamType.XSalsa20
		    CheckSize(Nonce, crypto_stream_noncebytes)
		    If crypto_stream(mb, mb.Size, Nonce, mKey.Value) <> 0 Then mb = Nil
		    
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
		  
		  If Data.Size < 0 Then Raise New SodiumException(ERR_SIZE_REQUIRED) ' can't pass a MemoryBlock of unknown size
		  
		  Dim output As New MemoryBlock(Data.Size)
		  Select Case Type
		  Case StreamType.ChaCha20
		    CheckSize(Nonce, crypto_stream_chacha20_noncebytes)
		    If crypto_stream_chacha20_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  Case StreamType.XChaCha20
		    CheckSize(Nonce, crypto_stream_xchacha20_noncebytes)
		    If crypto_stream_xchacha20_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  Case StreamType.Salsa20
		    CheckSize(Nonce, crypto_stream_salsa20_noncebytes)
		    If crypto_stream_salsa20_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  Case StreamType.XSalsa20
		    CheckSize(Nonce, crypto_stream_noncebytes)
		    If crypto_stream_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then output = Nil
		    
		  End Select
		  
		  Return output
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce(Type As libsodium.StreamType = libsodium.StreamType.XSalsa20) As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a Nonce for use with KeyStream.Process
		  ' and KeyStream.DeriveKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.RandomNonce
		  
		  Dim sz As Integer
		  Select Case Type
		  Case StreamType.ChaCha20
		    sz = crypto_stream_chacha20_noncebytes
		  Case StreamType.XChaCha20
		    sz = crypto_stream_xchacha20_noncebytes
		  Case StreamType.Salsa20
		    sz = crypto_stream_salsa20_noncebytes
		  Case StreamType.XSalsa20
		    sz = crypto_stream_noncebytes
		  End Select
		  
		  Return RandomBytes(sz)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Type() As libsodium.StreamType
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
		Protected mType As libsodium.StreamType = libsodium.StreamType.XSalsa20
	#tag EndProperty


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
