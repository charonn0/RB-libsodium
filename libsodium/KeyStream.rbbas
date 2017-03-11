#tag Class
Protected Class KeyStream
	#tag Method, Flags = &h0
		Sub Constructor()
		  ' Generates a random key stream.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  Me.Constructor(RandomBytes(crypto_stream_KEYBYTES))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(FromPassword As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' Generates a key stream by deriving it from a salted hash of the password. The operation is
		  ' deterministic, such that calling this method twice with the same Password, Salt, and Limits
		  ' parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.Constructor
		  
		  If Salt = Nil Then Salt = FromPassword.RandomSalt(HashAlgorithm)
		  Me.Constructor(FromPassword.DeriveKey(crypto_stream_KEYBYTES, Salt, Limits, HashAlgorithm))
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
		  
		  If Nonce = Nil Then Nonce = Me.RandomNonce()
		  CheckSize(Nonce, crypto_stream_NONCEBYTES)
		  Dim mb As New MemoryBlock(Size)
		  If crypto_stream(mb, mb.Size, Nonce, mKey.Value) <> 0 Then Return Nil
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
		  
		  CheckSize(Nonce, crypto_stream_NONCEBYTES)
		  Dim output As New MemoryBlock(Data.Size)
		  If crypto_stream_xor(output, Data, Data.Size, Nonce, mKey.Value) <> 0 Then Return Nil
		  Return output
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns random bytes that are suitable to be used as a Nonce for use with KeyStream.Process
		  ' and KeyStream.DeriveKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.KeyStream.RandomNonce
		  
		  Return RandomBytes(crypto_stream_NONCEBYTES)
		End Function
	#tag EndMethod


	#tag Note, Name = About key streams
		The DeriveKey method, viewed as a function of the nonce for a uniform random key, is designed to meet the standard notion
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


	#tag Constant, Name = crypto_stream_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_stream_NONCEBYTES, Type = Double, Dynamic = False, Default = \"24", Scope = Private
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
