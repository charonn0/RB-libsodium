#tag Class
Protected Class SodiumException
Inherits RuntimeException
	#tag Method, Flags = &h0
		Sub Constructor(ErrorNumber As Integer)
		  Select Case ErrorNumber 
		  Case ERR_INIT_FAILED
		    Me.Message = "libsodium could not be initialized."
		    
		  Case ERR_UNAVAILABLE
		    Me.Message = "libsodium is not installed or failed to initialize."
		    
		  Case ERR_PROTECT_FAILED
		    Me.Message = "Unable to set the memory protection level."
		    
		  Case ERR_CANT_ALLOC
		    Me.Message = "Unable to create buffer of the requested size."
		    
		  Case ERR_TOO_LARGE
		    Me.Message = "The data is too large for the buffer."
		    
		  Case ERR_READ_DENIED
		    Me.Message = "The requested memory is secured and cannot be accessed."
		    
		  Case ERR_WRITE_DENIED
		    Me.Message = "The requested memory is secured and cannot be modified."
		    
		  Case ERR_LOCK_DENIED
		    Me.Message = "The requested memory lock could not be modified."
		    
		  Else
		    Me.Message = "Unknown error in libsodium."
		    
		  End Select
		End Sub
	#tag EndMethod


	#tag ViewBehavior
		#tag ViewProperty
			Name="ErrorNumber"
			Group="Behavior"
			InitialValue="0"
			Type="Integer"
			InheritedFrom="RuntimeException"
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
			Name="Message"
			Group="Behavior"
			Type="String"
			EditorType="MultiLineEditor"
			InheritedFrom="RuntimeException"
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
