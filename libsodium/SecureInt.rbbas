#tag Class
Protected Class SecureInt
	#tag Method, Flags = &h1
		Protected Sub Constructor(InitialValue As UInt64)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_INIT_FAILED)
		  Call Me.Operator_Add(0)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Increment()
		  sodium_increment(mIntPtr, mSize)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Add(Addend As UInt64) As UInt64
		  Dim rightoperand As New SecureInt(Addend)
		  sodium_add(mIntPtr, rightoperand.mIntPtr, mSize)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_AddRight(Addend As UInt64) As UInt64
		  Dim leftoperand As New SecureInt(Addend)
		  sodium_add(leftoperand.mIntPtr, mIntPtr, leftoperand.mSize)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_And(LogicalValue As UInt64) As Boolean
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_AndRight(LogicalValue As UInt64) As Boolean
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherInt As libsodium.SecureInt) As Integer
		  Return sodium_compare(mIntPtr, OtherInt.mIntPtr, mSize)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Convert() As UInt64
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromInt As UInt64)
		  Me.Constructor(FromInt)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Divide(Demoninator As UInt64) As UInt64
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_DivideRight(Numerator As UInt64) As UInt64
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mIntPtr As Ptr
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mSize As UInt64
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
