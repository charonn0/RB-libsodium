#tag Class
Class SecureArray
Inherits libsodium.SecureMemory
	#tag Method, Flags = &h0
		Sub Constructor(Count As UInt64, FieldSize As UInt64)
		  Super.Constructor()
		  mPtr = sodium_allocarray(Count, FieldSize)
		  If mPtr = Nil Then Raise New SodiumException("Unable to create a secure array of the requested size.")
		  mFieldSize = FieldSize
		  mCount = Count
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mPtr <> Nil Then sodium_free(mPtr)
		  mPtr = Nil
		  mFieldSize = 0
		  mCount = 0
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Subscript(Index As Integer) As libsodium.SecureMemoryBlock
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mCount As UInt64
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mFieldSize As UInt64
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
