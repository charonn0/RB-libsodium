#tag Class
Protected Class KeyPair
Implements libsodium.Secureable
	#tag Method, Flags = &h1001
		Protected Sub Constructor(PrivateKeyData As MemoryBlock, PublicKeyData As MemoryBlock)
		  mPrivate = New libsodium.SKI.KeyContainter(PrivateKeyData)
		  mPublic = PublicKeyData
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  // Part of the libsodium.Secureable interface.
		  
		  Secureable(mPrivate).Lock()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PrivateKey() As MemoryBlock
		  Return mPrivate.Value()
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PublicKey() As MemoryBlock
		  Return mPublic
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  // Part of the libsodium.Secureable interface.
		  
		  Secureable(mPrivate).Unlock()
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mPrivate As libsodium.SKI.KeyContainter
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPublic As MemoryBlock
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
