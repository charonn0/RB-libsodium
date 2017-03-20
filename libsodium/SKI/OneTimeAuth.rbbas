#tag Module
Protected Module OneTimeAuth
	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_onetimeauth Lib "libsodium" (Buffer As Ptr, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag ExternalMethod, Flags = &h21
		Private Soft Declare Function crypto_onetimeauth_verify Lib "libsodium" (Signature As Ptr, Message As Ptr, MessageLength As UInt64, SecretKey As Ptr) As Int32
	#tag EndExternalMethod

	#tag Method, Flags = &h1
		Protected Function GenerateMAC(Message As MemoryBlock, Key As libsodium.SKI.SecretKey, Exportable As Boolean = False) As MemoryBlock
		  ' Generate a Poly1305 *one-time* authentication code for the Message using SecretKey. Due
		  ' to its small output size, Poly1305 is recommended for online protocols, exchanging many
		  ' small messages, rather than for authenticating very large files.
		  ' NOTE: Never reuse a key with this function; a new key is required for every message.
		  '
		  ' See: https://download.libsodium.org/doc/advanced/poly1305.html
		  
		  CheckSize(Key.Value, crypto_onetimeauth_KEYBYTES)
		  
		  Dim authenticator As New MemoryBlock(crypto_onetimeauth_BYTES)
		  If crypto_onetimeauth(authenticator, Message, Message.Size, Key.Value) = 0 Then
		    If Exportable Then authenticator = libsodium.Exporting.Export(authenticator, libsodium.Exporting.ExportableType.HMAC)
		    Return authenticator
		  End If
		End Function
	#tag EndMethod

	#tag Method, Flags = &h1
		Protected Function VerifyMAC(Authenticator As MemoryBlock, Message As MemoryBlock, Key As libsodium.SKI.SecretKey) As Boolean
		  ' Validate the Poly1305 *one-time* authentication code for the Message using SecretKey. Due
		  ' to its small output size, Poly1305 is recommended for online protocols, exchanging many
		  ' small messages, rather than for authenticating very large files.
		  '
		  ' See: https://download.libsodium.org/doc/advanced/poly1305.html
		  
		  CheckSize(Key.Value, crypto_onetimeauth_KEYBYTES)
		  If Left(Authenticator, 5) = "-----" Then Authenticator = libsodium.Exporting.Import(Authenticator)
		  If Left(Message, 5) = "-----" Then Message = libsodium.Exporting.Import(Message)
		  Return crypto_onetimeauth_verify(Authenticator, Message, Message.Size, Key.Value) = 0
		End Function
	#tag EndMethod


	#tag Constant, Name = crypto_onetimeauth_BYTES, Type = Double, Dynamic = False, Default = \"16", Scope = Private
	#tag EndConstant

	#tag Constant, Name = crypto_onetimeauth_KEYBYTES, Type = Double, Dynamic = False, Default = \"32", Scope = Private
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
End Module
#tag EndModule
