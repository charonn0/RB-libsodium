#tag Class
Protected Class RandomProvider
	#tag Method, Flags = &h0
		Sub Constructor(Name As String)
		  mName = Name
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Shared Sub RandomBytesCallback(Buffer As MemoryBlock, Size As UInt64)
		  
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mName As String
	#tag EndProperty


	#tag Structure, Name = randombytes_implementation, Flags = &h1
		Name As Ptr
		  RandomInt As Ptr
		  Stir As Ptr
		  UnformInt As Ptr
		  GenRandom As Ptr
		CloseFunc As Ptr
	#tag EndStructure


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
