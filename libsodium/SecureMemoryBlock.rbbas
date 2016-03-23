#tag Class
Class SecureMemoryBlock
Inherits libsodium.SecureMemory
	#tag Method, Flags = &h0
		Sub Constructor(Size As UInt64)
		  Super.Constructor()
		  mPtr = sodium_malloc(Size)
		  If mPtr = Nil Then Raise New SodiumException("Unable to create a secure memory block of the requested size.")
		  mSize = Size
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mPtr <> Nil Then
		    If mProtectionLevel <> libsodium.MemoryProtectionLevel.ReadWrite Then Me.ProtectionLevel = libsodium.MemoryProtectionLevel.ReadWrite
		    If Not mAllowSwap Then Me.AllowSwap = True
		    sodium_free(mPtr)
		  End If
		  mPtr = Nil
		  mSize = 0
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function StringValue(Offset As UInt64, Length As UInt64) As MemoryBlock
		  If mProtectionLevel = libsodium.MemoryProtectionLevel.NoAccess Then Raise New SodiumException("The requested memory is secured and cannot be accessed.")
		  Dim mb As MemoryBlock = mPtr
		  Return mb.StringValue(Offset, Length)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub StringValue(Offset As UInt64, Length As UInt64, Assigns NewData As MemoryBlock)
		  If mProtectionLevel <> libsodium.MemoryProtectionLevel.ReadWrite Then Raise New SodiumException("The requested memory is secured and cannot be modified.")
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
			  If i = -1 Then Raise New SodiumException("The requested memory lock could not be modified.")
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

	#tag Property, Flags = &h21
		Private mSize As UInt64
	#tag EndProperty


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
