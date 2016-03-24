#tag Class
Class SecureMemoryBlock
	#tag Method, Flags = &h1000
		Sub Constructor(SecuredArray As libsodium.SecureArray, Index As Integer)
		  #pragma Warning "Fixme"
		  'If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_INIT_FAILED)
		  'mFreeable = False
		  'mSize = SecuredArray.FieldSize
		  'Dim op As Int32 = Int32(SecuredArray.mPtr) + (Index * mSize)
		  'mPtr = Ptr(op)
		  
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Constructor(Size As UInt64)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_INIT_FAILED)
		  mPtr = sodium_malloc(Size)
		  If mPtr = Nil Then Raise New SodiumException(ERR_CANT_ALLOC)
		  mSize = Size
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mPtr <> Nil And mFreeable Then
		    If mProtectionLevel <> libsodium.MemoryProtectionLevel.ReadWrite Then Me.ProtectionLevel = libsodium.MemoryProtectionLevel.ReadWrite
		    If Not mAllowSwap Then Me.AllowSwap = True
		    sodium_free(mPtr)
		  End If
		  mPtr = Nil
		  mSize = 0
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Size() As UInt64
		  Return mSize
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function StringValue(Offset As UInt64, Length As UInt64) As MemoryBlock
		  If mProtectionLevel = libsodium.MemoryProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.StringValue(Offset, Length)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub StringValue(Offset As UInt64, Length As UInt64, Assigns NewData As MemoryBlock)
		  If mProtectionLevel <> libsodium.MemoryProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  mb.StringValue(Offset, Length) = NewData
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub ZeroFill()
		  If mPtr = Nil Then Return
		  sodium_memzero(mPtr, mSize)
		End Sub
	#tag EndMethod


	#tag ComputedProperty, Flags = &h0
		#tag Getter
			Get
			  return mAllowSwap
			End Get
		#tag EndGetter
		#tag Setter
			Set
			  Dim i As Integer
			  If value Then
			    i = sodium_munlock(mPtr, mSize)
			  Else
			    i = sodium_mlock(mPtr, mSize)
			  End If
			  If i = -1 Then Raise New SodiumException(ERR_LOCK_DENIED)
			  mAllowSwap = value
			End Set
		#tag EndSetter
		AllowSwap As Boolean
	#tag EndComputedProperty

	#tag Property, Flags = &h21
		Private mAllowSwap As Boolean = True
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mFreeable As Boolean = True
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mProtectionLevel As libsodium.MemoryProtectionLevel = libsodium.MemoryProtectionLevel.ReadWrite
	#tag EndProperty

	#tag Property, Flags = &h1
		Protected mPtr As Ptr
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mSize As UInt64
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
			  Case libsodium.MemoryProtectionLevel.ReadWrite
			    i = sodium_mprotect_readwrite(mPtr)
			  Case libsodium.MemoryProtectionLevel.ReadOnly
			    i = sodium_mprotect_readonly(mPtr)
			  Case libsodium.MemoryProtectionLevel.NoAccess
			    i = sodium_mprotect_noaccess(mPtr)
			  End Select
			  If i = -1 Then Raise New SodiumException(ERR_PROTECT_FAILED)
			  mProtectionLevel = value
			End Set
		#tag EndSetter
		ProtectionLevel As libsodium.MemoryProtectionLevel
	#tag EndComputedProperty


	#tag ViewBehavior
		#tag ViewProperty
			Name="AllowSwap"
			Group="Behavior"
			Type="Boolean"
		#tag EndViewProperty
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
