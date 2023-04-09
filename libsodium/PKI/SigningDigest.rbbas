#tag Class
Protected Class SigningDigest
	#tag Method, Flags = &h0
		Sub Constructor()
		  ' Instantiates the digest operation. If libsodium has the multipart crypto_sign api then
		  ' we use it. Otherwise we use the GenericHashDigest to compute a SHA512 hash of the
		  ' input. These two modes are equivalent but not identical, such that a signature from one
		  ' will not validate in the other.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningDigest.Constructor
		  
		  If System.IsFunctionAvailable("crypto_sign_init", sodium) Then
		    mState = New MemoryBlock(crypto_sign_ed25519ph_statebytes)
		    If crypto_sign_init(mState) <> 0 Then Raise New SodiumException(ERR_INIT_FAILED)
		  Else
		    Me.Constructor(HashType.SHA512)
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(HashAlgorithm As libsodium.HashType)
		  ' Instantiates the digest operation using either blake2b or SHA512; SHA256 is not allowed. 
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningDigest.Constructor
		  
		  If HashAlgorithm = HashType.SHA256 Then Raise New SodiumException(ERR_UNSUITABLE)
		  mDigest = New GenericHashDigest(HashAlgorithm)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mState <> Nil Then
		    Static fake As SigningKey = SigningKey.Generate()
		    Call Me.Sign(fake)
		  End If
		  If mDigest <> Nil Then
		    Call mDigest.Value()
		    mDigest = Nil
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Process(NewData As MemoryBlock)
		  ' Process the NewData into the running hash.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningDigest.Process
		  
		  If mDigest = Nil Then
		    ProcessEd25519ph(NewData)
		  Else
		    ProcessSHA512(NewData)
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ProcessEd25519ph(NewData As MemoryBlock)
		  If mState = Nil Then Raise New SodiumException(ERR_INVALID_STATE)
		  If crypto_sign_update(mState, NewData, NewData.Size) <> 0 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ProcessSHA512(NewData As MemoryBlock)
		  mDigest.Process(NewData)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Reset()
		  ' Resets the processor state so that a new signature can be computed.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningDigest.Reset
		  
		  Select Case True
		  Case mDigest <> Nil
		    mDigest.Reset()
		  Case mState <> Nil
		    Me.Constructor()
		  End Select
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Sign(SenderKey As libsodium.PKI.SigningKey) As MemoryBlock
		  ' Finalizes the hash operation and then signs the result with the SenderKey. On
		  ' success the signature is returned; on error Nil is returned. After calling this
		  ' method (regardless of success) no other methods (Process, Verify, etc.) may be
		  ' called nor can this method be called twice.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningDigest.Sign
		  
		  If mDigest = Nil Then
		    Return SignFinalEd25519ph(SenderKey)
		  Else
		    Return SignFinalSHA512(SenderKey)
		  End If
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function SignFinalEd25519ph(SenderKey As libsodium.PKI.SigningKey) As MemoryBlock
		  If mState = Nil Then Return Nil
		  Dim sig As MemoryBlock = New MemoryBlock(crypto_sign_bytes)
		  Dim sigsz As UInt64 = sig.Size
		  If crypto_sign_final_create(mState, sig, sigsz, SenderKey.PrivateKey) <> 0 Then Return Nil
		  sig.Size = sigsz
		  mState = Nil
		  Return sig
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function SignFinalSHA512(SenderKey As libsodium.PKI.SigningKey) As MemoryBlock
		  Dim sig As MemoryBlock = libsodium.PKI.SignData(mDigest.Value, SenderKey, True)
		  mDigest = Nil
		  Return sig
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Verify(SenderKey As libsodium.PKI.PublicKey, Signature As MemoryBlock) As Boolean
		  ' Finalizes the hash operation and then verifies the Signature with the SenderKey.
		  ' Returns True if the Signature is valid. After calling this method (regardless of
		  ' success) no other methods (Process, Sign, etc.) may be called nor can this method
		  ' be called twice.
		  '
		  ' See:
		  ' https://github.com/charonn0/RB-libsodium/wiki/libsodium.PKI.SigningDigest.Verify
		  
		  If mDigest = Nil Then
		    Return VerifyFinalEd25519ph(SenderKey, Signature)
		  Else
		    Return VerifyFinalSHA512(SenderKey, Signature)
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function VerifyFinalEd25519ph(SenderKey As libsodium.PKI.PublicKey, Signature As MemoryBlock) As Boolean
		  If mState = Nil Then Return False
		  Dim ok As Boolean = (crypto_sign_final_verify(mState, Signature, SenderKey.Value) = 0)
		  mState = Nil
		  Return ok
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Function VerifyFinalSHA512(SenderKey As libsodium.PKI.PublicKey, Signature As MemoryBlock) As Boolean
		  Dim ok As Boolean = libsodium.PKI.VerifyData(mDigest.Value, SenderKey, Signature)
		  mDigest = Nil
		  Return ok
		End Function
	#tag EndMethod


	#tag Note, Name = About this class
		Use this class as an alternative to libsodium.PKI.SignData/VerifyData for messages that are too large to fit into memory.
	#tag EndNote


	#tag Property, Flags = &h21
		Private mDigest As GenericHashDigest
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mState As MemoryBlock
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
