#tag Class
Protected Class Password
	#tag Method, Flags = &h0
		Sub Constructor(Passwd As libsodium.SecureMemoryBlock)
		  If Not libsodium.IsAvailable Then Raise New SodiumException(ERR_INIT_FAILED)
		  mPassword = Passwd
		  mPassword.AllowSwap = False
		  Me.Lock()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function DeriveKey(KeyLength As Integer, Salt As MemoryBlock, OpsLimit As Integer, MemLimit As Integer, Algorithm As Integer) As MemoryBlock
		  Dim out As New MemoryBlock(KeyLength)
		  Me.Unlock()
		  Try
		    If crypto_pwhash( _
		      out, out.Size, _
		      mPassword.StringValue(0, mPassword.Size), mPassword.Size, _
		      Salt, _
		      OpsLimit, _
		      MemLimit, _
		      Algorithm) = -1 Then Raise New SodiumException(ERR_COMPUTATION_FAILED)
		      
		      Return out
		      
		  Finally
		    Me.Lock()
		  End Try
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Destructor()
		  If mPassword <> Nil Then mPassword.ZeroFill()
		  mPassword = Nil
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Lock()
		  mPassword.ProtectionLevel = libsodium.ProtectionLevel.NoAccess
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Operator_Compare(OtherPassword As libsodium.SecureMemoryBlock) As Integer
		  If libsodium.StrComp(mPassword.StringValue(0, mPassword.Size), OtherPassword.StringValue(0, OtherPassword.Size)) Then Return 0
		  Return -1
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Sub Unlock()
		  mPassword.ProtectionLevel = libsodium.ProtectionLevel.ReadOnly
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function Value() As libsodium.SecureMemoryBlock
		  Me.Unlock()
		  Dim ret As New SecureMemoryBlock(mPassword.Size)
		  Try
		    ret.StringValue(0, ret.Size) = mPassword.StringValue(0, mPassword.Size)
		  Finally
		    Me.Lock()
		  End Try
		  Return ret
		End Function
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mPassword As libsodium.SecureMemoryBlock
	#tag EndProperty


	#tag Constant, Name = MEMLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"33554432", Scope = Public
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_MODERATE, Type = Double, Dynamic = False, Default = \"134217728", Scope = Public
	#tag EndConstant

	#tag Constant, Name = MEMLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"536870912", Scope = Public
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_INTERACTIVE, Type = Double, Dynamic = False, Default = \"4", Scope = Public
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_MODERATE, Type = Double, Dynamic = False, Default = \"6", Scope = Public
	#tag EndConstant

	#tag Constant, Name = OPSLIMIT_SENSITIVE, Type = Double, Dynamic = False, Default = \"8", Scope = Public
	#tag EndConstant


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
