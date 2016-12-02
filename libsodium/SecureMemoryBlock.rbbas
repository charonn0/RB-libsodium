#tag Class
Class SecureMemoryBlock
	#tag Method, Flags = &h0
		Function BooleanValue(Offset As UInt64) As Boolean
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.BooleanValue(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub BooleanValue(Offset As UInt64, Assigns NewBool As Boolean)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 1 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.BooleanValue(Offset) = NewBool
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ByteValue(Offset As UInt64) As Byte
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 1 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.Byte(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub ByteValue(Offset As UInt64, Assigns NewByte As Byte)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 1 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.Byte(Offset) = NewByte
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function ColorValue(Offset As UInt64, Bits As Integer) As Color
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.ColorValue(Offset, Bits)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub ColorValue(Offset As UInt64, Bits As Integer, Assigns NewColor As Color)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.ColorValue(Offset, Bits) = NewColor
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1000
		Sub Constructor(SecuredArray As libsodium.SecureArray, Index As Integer)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_INIT_FAILED)
		  mFreeable = False
		  mSize = SecuredArray.FieldSize
		  Dim op As Int32 = Int32(SecuredArray.TruePtr) + (Index * mSize)
		  mPtr = Ptr(op)
		  
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

	#tag Method, Flags = &h0
		Function CString(Offset As UInt64) As CString
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.CString(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub CString(Offset As UInt64, Assigns NewString As CString)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + NewString.LenB > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.CString(Offset) = NewString
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function CurrencyValue(Offset As UInt64) As Currency
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.CurrencyValue(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub CurrencyValue(Offset As UInt64, Assigns NewCurrency As Currency)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.CurrencyValue(Offset) = NewCurrency
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mPtr <> Nil And mFreeable Then
		    Try
		      If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Me.ProtectionLevel = libsodium.ProtectionLevel.ReadWrite
		      If Not mAllowSwap Then Me.AllowSwap = True
		    Finally
		      sodium_free(mPtr)
		    End Try
		  End If
		  mPtr = Nil
		  mSize = 0
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DoubleValue(Offset As UInt64) As Double
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.DoubleValue(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DoubleValue(Offset As UInt64, Assigns NewDouble As Double) As Double
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.DoubleValue(Offset) = NewDouble
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Int16Value(Offset As UInt64) As Int16
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 2 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.Int16Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Int16Value(Offset As UInt64, Assigns NewInt As Int16)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 2 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.Int16Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Int32Value(Offset As UInt64) As Int32
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.Int32Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Int32Value(Offset As UInt64, Assigns NewInt As Int32)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.Int16Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Int64Value(Offset As UInt64) As Int64
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.Int64Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Int64Value(Offset As UInt64, Assigns NewInt As Int64)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.Int64Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Long(Offset As UInt64) As Integer
		  Return Me.Int32Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Long(Offset As UInt64, Assigns NewInt As Integer)
		  Me.Int32Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherMB As libsodium.SecureMemoryBlock) As Integer
		  If OtherMB Is Nil Then Return 1
		  If sodium_memcmp(mPtr, OtherMB.mPtr, Max(mSize, OtherMB.Size)) = 0 Then Return 0
		  If OtherMB.Size > mSize Then Return -1
		  If OtherMB.Size < mSize Then Return 1
		  If OtherMB.Size > mSize Then Return -1
		  Return Sign(Integer(mPtr) - Integer(OtherMB.mPtr))
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherMB As String) As Integer
		  If libsodium.StrComp(Me.StringValue(0, Me.LenB), OtherMB) Then Return 0
		  If OtherMB.LenB < Me.Size Then Return 1
		  Return -1
		  
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Convert() As String
		  Return Me.StringValue(0, mSize)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub Operator_Convert(FromString As String)
		  Me.Constructor(FromString.LenB)
		  Me.StringValue(0, FromString.LenB) = FromString
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function PString(Offset As UInt64) As PString
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.PString(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub PString(Offset As UInt64, Assigns NewString As PString)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + NewString.LenB > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.PString(Offset) = NewString
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function SingleValue(Offset As UInt64) As Single
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.SingleValue(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub SingleValue(Offset As UInt64, Assigns NewInt As Single)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.SingleValue(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Size() As UInt64
		  Return mSize
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function StringValue(Offset As UInt64, Length As UInt64) As MemoryBlock
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.StringValue(Offset, Length)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub StringValue(Offset As UInt64, Length As UInt64, Assigns NewData As MemoryBlock)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + Length > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.StringValue(Offset, Length) = NewData
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function TruePtr() As Ptr
		  Return mPtr
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UInt16Value(Offset As UInt64) As UInt16
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 2 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.UInt16Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub UInt16Value(Offset As UInt64, Assigns NewInt As UInt16)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 2 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.UInt16Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UInt32Value(Offset As UInt64) As UInt32
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.UInt32Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub UInt32Value(Offset As UInt64, Assigns NewInt As UInt32)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 4 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.UInt16Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UInt64Value(Offset As UInt64) As UInt64
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.UInt64Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub UInt64Value(Offset As UInt64, Assigns NewInt As UInt64)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 8 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.UInt64Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UInt8Value(Offset As UInt64) As UInt8
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  If Offset + 1 > mSize Then Raise New SodiumException(ERR_OUT_OF_BOUNDS)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.UInt8Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub UInt8Value(Offset As UInt64, Assigns NewInt As UInt8)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + 1 > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.UInt8Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function UShortValue(Offset As UInt64) As UInt16
		  Return Me.UInt16Value(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub UShortValue(Offset As UInt64, Assigns NewInt As UInt16)
		  Me.UInt16Value(Offset) = NewInt
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function WString(Offset As UInt64) As WString
		  If mProtectionLevel = libsodium.ProtectionLevel.NoAccess Then Raise New SodiumException(ERR_READ_DENIED)
		  Dim mb As MemoryBlock = mPtr
		  Return mb.WString(Offset)
		End Function
	#tag EndMethod

	#tag Method, Flags = &h0
		Sub WString(Offset As UInt64, Assigns NewString As WString)
		  If mProtectionLevel <> libsodium.ProtectionLevel.ReadWrite Then Raise New SodiumException(ERR_WRITE_DENIED)
		  If Offset + NewString.LenB > mSize Then Raise New SodiumException(ERR_TOO_LARGE)
		  Dim mb As MemoryBlock = mPtr
		  mb.WString(Offset) = NewString
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
		Protected mProtectionLevel As libsodium.ProtectionLevel = libsodium.ProtectionLevel.ReadWrite
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
