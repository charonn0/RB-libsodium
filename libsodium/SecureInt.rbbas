#tag Class
Protected Class SecureInt
	#tag Method, Flags = &h0
		Function Operator_Add(Addend As Int64) As Int64
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_AddRight(Addend As Int64) As Int64
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_And(LogicalValue As Int64) As Boolean
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_AndRight(LogicalValue As Int64) As Boolean
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherInt As libsodium.SecureInt) As Integer
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Convert() As Int64
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromInt As Int64)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Divide(Demoninator As Int64) As Int64
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_DivideRught(Numerator As Int64) As Int64
		  
		End Function
	#tag EndMethod


	#tag Property, Flags = &h1
		Protected mIntPtr As Ptr
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
