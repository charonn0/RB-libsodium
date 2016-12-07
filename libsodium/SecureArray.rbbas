#tag Class
Class SecureArray
	#tag Method, Flags = &h0
		Sub Constructor(Count As UInt64, FieldSize As UInt64)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_UNAVAILABLE)
		  mPtr = sodium_allocarray(Count, FieldSize)
		  If mPtr = Nil Then Raise New SodiumException(ERR_CANT_ALLOC)
		  mFieldSize = FieldSize
		  mCount = Count
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Count() As UInt64
		  Return mCount
		End Function
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
		Function FieldSize() As UInt64
		  Return mFieldSize
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Subscript(Index As Integer) As libsodium.SecureMemoryBlock
		  Return New libsodium.SecureMemoryBlock(Me, Index)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Subscript(Index As Integer, Assigns NewData As libsodium.SecureMemoryBlock)
		  If NewData.Size > mFieldSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As New libsodium.SecureMemoryBlock(Me, Index)
		  mb.StringValue(0, NewData.Size) = NewData.StringValue(0, NewData.Size)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function TruePtr() As Ptr
		  Return mPtr
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mCount As UInt64
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mFieldSize As UInt64
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mProtectionLevel As libsodium.ProtectionLevel = libsodium.ProtectionLevel.ReadWrite
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPtr As Ptr
	#tag EndProperty

	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  return mProtectionLevel
			End Get
		#tag EndGetter
		#tag Setter
			Set
			  Dim i As Integer
			  Select Case value
			  Case libsodium.ProtectionLevel.ReadWrite
			    i = sodium_mprotect_readwrite(mPtr)
			  Case libsodium.ProtectionLevel.ReadOnly
			    i = sodium_mprotect_readonly(mPtr)
			  Case libsodium.ProtectionLevel.NoAccess
			    i = sodium_mprotect_noaccess(mPtr)
			  End Select
			  If i = -1 Then Raise New SodiumException(ERR_PROTECT_FAILED)
			  mProtectionLevel = value
			End Set
		#tag EndSetter
		ProtectionLevel As libsodium.ProtectionLevel
	#tag EndComputedProperty


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
