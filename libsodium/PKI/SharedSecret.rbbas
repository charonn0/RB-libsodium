#tag Class
Protected Class SharedSecret
Inherits libsodium.SKI.KeyContainer
	#tag Method, Flags = &h1000
		Sub Constructor(RecipientPublicKey As libsodium.PKI.ForeignKey, SenderPrivateKey As libsodium.PKI.EncryptionKey)
		  ' Derives the shared key from the public half of the recipient's key pair and the
		  ' private half of the sender's key pair. This allows the key derivation calculation
		  ' to be performed once rather than on each Encrypt/Decrypt operation.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html#precalculation-interface
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SharedSecret.Constructor
		  
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  CheckSize(RecipientPublicKey.Value, crypto_box_publickeybytes)
		  
		  Dim buffer As New MemoryBlock(crypto_box_beforenmbytes)
		  If crypto_box_beforenm(buffer, RecipientPublicKey.Value, SenderPrivateKey.PrivateKey) <> 0 Then
		    Raise New SodiumException(ERR_COMPUTATION_FAILED)
		  End If
		  Me.Constructor(buffer)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1001
		Protected Sub Constructor(SharedKey As MemoryBlock)
		  CheckSize(SharedKey, crypto_box_beforenmbytes)
		  // Calling the overridden superclass constructor.
		  // Constructor(KeyData As MemoryBlock) -- From KeyContainer
		  Super.Constructor(SharedKey)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function DeriveSharedSecret(RecipientPublicKey As MemoryBlock, SenderPrivateKey As libsodium.PKI.EncryptionKey) As MemoryBlock
		  ' WARNING: THIS IS (PROBABLY) NOT THE METHOD YOU'RE LOOKING FOR. You probably
		  ' want Constructor(TheirPublicKey, YourPrivateKey)
		  '
		  ' This method computes a shared secret (NOT a key) given a SenderPrivateKey and
		  ' RecipientPublicKey. The return value represents the X coordinate of a point on
		  ' the curve. As a result, the number of possible keys is limited to the group
		  ' size (≈2^252), and the key distribution is not uniform.
		  '
		  ' For this reason, instead of directly using the return value as a shared key,
		  ' it is recommended to use:
		  '
		  '    GenericHash(return value + RecipientPublicKey + Sender's PUBLIC KEY)
		  '
		  ' Or just call the Constructor, which does it for you.
		  '
		  ' See:
		  ' https://download.libsodium.org/doc/advanced/scalar_multiplication.html
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SharedSecret.DeriveSharedSecret
		  
		  CheckSize(RecipientPublicKey, crypto_scalarmult_bytes)
		  
		  Dim buffer As New MemoryBlock(crypto_scalarmult_bytes)
		  If crypto_scalarmult(buffer, SenderPrivateKey.PrivateKey, RecipientPublicKey) = 0 Then
		    Return buffer
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Export(SaveTo As FolderItem, Optional Passwd As libsodium.Password, OverWrite As Boolean = False) As Boolean
		  ' Exports the EncryptionKey in a format that is understood by EncryptionKey.Import(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Export
		  
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
		  ' Exports the EncryptionKey in a format that is understood by EncryptionKey.Import
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.Export
		  
		  Dim data As New MemoryBlock(0)
		  Dim bs As New BinaryStream(data)
		  
		  bs.Write(libsodium.Exporting.Export(Me.Value, libsodium.Exporting.ExportableType.SharedSecret, Passwd))
		  
		  bs.Close
		  Return data
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As FolderItem, Optional Passwd As libsodium.Password) As libsodium.PKI.SharedSecret
		  ' Import a SharedSecret that was exported using SharedSecret.Export(FolderItem)
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SharedSecret.Import
		  
		  Dim bs As BinaryStream = BinaryStream.Open(ExportedKey)
		  Dim keydata As MemoryBlock = bs.Read(bs.Length)
		  bs.Close
		  Return Import(keydata, Passwd)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function Import(ExportedKey As MemoryBlock, Optional Passwd As libsodium.Password) As libsodium.PKI.SharedSecret
		  ' Import a SharedSecret that was exported using SharedSecret.Export
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SharedSecret.Import
		  
		  libsodium.Exporting.AssertType(ExportedKey, libsodium.Exporting.ExportableType.SharedSecret)
		  Dim secret As MemoryBlock = libsodium.Exporting.Import(ExportedKey, Passwd)
		  If secret <> Nil Then Return New SharedSecret(secret)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherSecret As libsodium.PKI.SharedSecret) As Int32
		  If OtherSecret Is Nil Then Return 1
		  Return Super.Operator_Compare(OtherSecret.Value)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		 Shared Function RandomNonce() As MemoryBlock
		  ' Returns unpredictable bytes that are suitable to be used as a nonce in encryption.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.EncryptionKey.RandomNonce
		  
		  Return EncryptionKey.RandomNonce()
		End Function
	#tag EndMethod


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
