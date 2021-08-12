#tag Class
Protected Class SecretKey
Inherits libsodium.SKI.KeyContainer
	#tag Method, Flags = &h1000
		Sub Constructor(StreamData As libsodium.KeyStream, Optional Nonce As MemoryBlock)
		  ' Generates a key by deriving it from the KeyStream+Nonce. The operation is deterministic, such
		  ' that calling this method twice with the same parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Constructor
		  
		  If Nonce = Nil Then Nonce = StreamData.RandomNonce(StreamData.Type)
		  Me.Constructor(StreamData.DeriveKey(crypto_secretbox_keybytes, Nonce))
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(FromPassword As libsodium.Password, Optional Salt As MemoryBlock, Limits As libsodium.ResourceLimits = libsodium.ResourceLimits.Interactive, HashAlgorithm As Int32 = libsodium.Password.ALG_ARGON2)
		  ' Generates a secret key by deriving it from a salted hash of the password. The operation is
		  ' deterministic, such that calling this method twice with the same Password, Salt, and Limits
		  ' parameters will produce the same output both times.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Constructor
		  
		  If Salt = Nil Then Salt = FromPassword.RandomSalt(HashAlgorithm)
		  Dim key As MemoryBlock = FromPassword.DeriveKey(crypto_secretbox_keybytes, Salt, Limits, HashAlgorithm)
		  Me.Constructor(key)
		  mPasswdSalt = Salt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(KeyData As MemoryBlock)
		  CheckSize(KeyData, crypto_secretbox_keybytes)
		  // Calling the overridden superclass constructor.
		  // Constructor(KeyData As MemoryBlock) -- From KeyContainer
		  Super.Constructor(KeyData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Derive(SecretKeyData As MemoryBlock) As libsodium.SKI.SecretKey
		  ' Uses the SecretKeyData as the SecretKey
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Derive
		  
		  Return New SecretKey(SecretKeyData)
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(SaveTo As FolderItem, Optional Passwd As libsodium.Password, OverWrite As Boolean = False) As Boolean
		  ' Exports the SecretKey in a format that is understood by SecretKey.Import(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Export
		  
		  Try
		    Dim bs As BinaryStream = BinaryStream.Create(SaveTo, OverWrite)
		    bs.Write(Me.Export(Passwd))
		    bs.Close
		  Catch Err As IOException
		    Return False
		  End Try
		  Return True
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(Optional Passwd As libsodium.Password) As MemoryBlock
		  ' Exports the SecretKey in a format that is understood by SecretKey.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Export
		  
		  Return libsodium.Exporting.Export(Me.Value, libsodium.Exporting.ExportableType.Secret, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1000
		 Shared Function Generate() As libsodium.SKI.SecretKey
		  ' Returns unpredictable bytes that are suitable to be used as a secret key.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Generate
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Return New libsodium.SKI.SecretKey(RandomBytes(crypto_secretbox_keybytes))
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As FolderItem, Optional Passwd As libsodium.Password) As libsodium.SKI.SecretKey
		  ' Import an SecretKey that was exported using SecretKey.Export(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Import
		  
		  Dim bs As BinaryStream = BinaryStream.Open(ExportedKey)
		  Dim keydata As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Return Import(keydata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As MemoryBlock, Optional Passwd As libsodium.Password) As libsodium.SKI.SecretKey
		  ' Import an SecretKey that was exported using SecretKey.Export
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.Import
		  
		  libsodium.Exporting.AssertType(ExportedKey, libsodium.Exporting.ExportableType.Secret)
		  Dim sk As MemoryBlock = libsodium.Exporting.Import(ExportedKey, Passwd)
		  If sk <> Nil Then Return New SecretKey(sk)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherKey As libsodium.SKI.SecretKey) As Int32
		  If OtherKey Is Nil Then Return 1
		  Return Super.Operator_Compare(OtherKey.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a Nonce.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.SKI.SecretKey.RandomNonce
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  Return RandomBytes(crypto_secretbox_noncebytes)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Salt() As MemoryBlock
		  ' If the Key was derived from a Password then this method will return the salt, otherwise it returns Nil.
		  
		  Return mPasswdSalt
		End Function
	#tag EndMethod


	#tag Note, Name = Usage
		This class contains a key for use with symmetric encryption and message authentication. Encryption, 
		decryption, and MAC generation/validation use the same key, so it must be kept secret at all times.
		
		You may use a SecretKey with the SecretStream class or these utility methods:
		
		  * libsodium.SKI.EncryptData: Encrypt a message and generate its MAC; the MAC is prepended to the 
		    encrypted message and returned.
		  * libsodium.SKI.DecryptData: Authenticate the MAC and return the decrypted the message.
		  * libsodium.SKI.GenerateMAC: Generate a MAC for an unencrypted message.
		  * libsodium.SKI.VerifyMAC: Authenticate a MAC for an unencrypted message.
		
		Encryption is done using the XSalsa20 stream cipher. Message authentication uses Poly1305 authentication codes.
		
		
		To generate a brand new secret key use the SecretKey.Generate() shared method:
		
		     Dim sk As libsodium.SKI.SecretKey
		     sk = sk.Generate()
		
		To derive a secret key from a password use the Constructor method. Derivation requires a random salt, which you 
		should get from the Password.RandomSalt() shared method:
		
		     Dim pw As libsodium.Password = "seekrit"
		     Dim salt As MemoryBlock = pw.RandomSalt()
		     Dim sk As New libsodium.SKI.SecretKey(pw, salt)
		
		
		Encryption/decryption needs a Nonce value to work. Use the SecretKey.RandomNonce shared method to generate
		securely random nonces (continuing from the above code): 
		
		    Dim n As MemoryBlock = sk.RandomNonce()
		    Dim msg As MemoryBlock = libsodium.SKI.EncryptData("Hello, world!", sk, n)
		    MsgBox(libsodium.SKI.DecryptData(msg, sk, n))
		
		See also the libsodium.IncrementNonce, libsodium.CombineNonce, and libsodium.CompareNonce utility methods.
	#tag EndNote


	#tag Property, Flags = &h21
		Private mPasswdSalt As MemoryBlock
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
