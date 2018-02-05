#tag Window
Begin Window SKIKeyGenDialog
   BackColor       =   16777215
   Backdrop        =   ""
   CloseButton     =   False
   Composite       =   False
   Frame           =   1
   FullScreen      =   False
   HasBackColor    =   False
   Height          =   1.05e+2
   ImplicitInstance=   False
   LiveResize      =   False
   MacProcID       =   0
   MaxHeight       =   32000
   MaximizeButton  =   False
   MaxWidth        =   32000
   MenuBar         =   ""
   MenuBarVisible  =   True
   MinHeight       =   64
   MinimizeButton  =   False
   MinWidth        =   64
   Placement       =   1
   Resizeable      =   False
   Title           =   "Generate a key"
   Visible         =   True
   Width           =   6.07e+2
   Begin Label PrivKeyLabel
      AutoDeactivate  =   True
      Bold            =   ""
      DataField       =   ""
      DataSource      =   ""
      Enabled         =   True
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   84
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   True
      LockTop         =   True
      Multiline       =   True
      Scope           =   2
      Selectable      =   False
      TabIndex        =   9
      TabPanelIndex   =   0
      Text            =   "(hidden)"
      TextAlign       =   0
      TextColor       =   0
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   14
      Transparent     =   True
      Underline       =   ""
      Visible         =   True
      Width           =   509
   End
   Begin Label Label3
      AutoDeactivate  =   True
      Bold            =   ""
      DataField       =   ""
      DataSource      =   ""
      Enabled         =   True
      Height          =   20
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   0
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Multiline       =   ""
      Scope           =   2
      Selectable      =   False
      TabIndex        =   10
      TabPanelIndex   =   0
      Text            =   "Secret key:"
      TextAlign       =   2
      TextColor       =   0
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   11
      Transparent     =   False
      Underline       =   ""
      Visible         =   True
      Width           =   81
   End
   Begin TextField SeedField
      AcceptTabs      =   ""
      Alignment       =   0
      AutoDeactivate  =   True
      AutomaticallyCheckSpelling=   False
      BackColor       =   16777215
      Bold            =   ""
      Border          =   True
      CueText         =   ""
      DataField       =   ""
      DataSource      =   ""
      Enabled         =   False
      Format          =   ""
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      Italic          =   ""
      Left            =   84
      LimitText       =   0
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   True
      LockTop         =   True
      Mask            =   ""
      Password        =   ""
      ReadOnly        =   ""
      Scope           =   2
      TabIndex        =   5
      TabPanelIndex   =   0
      TabStop         =   True
      Text            =   ""
      TextColor       =   0
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   39
      Underline       =   ""
      UseFocusRing    =   True
      Visible         =   True
      Width           =   482
   End
   Begin PushButton RndSeedBtn
      AutoDeactivate  =   True
      Bold            =   True
      ButtonStyle     =   0
      Cancel          =   ""
      Caption         =   "↻"
      Default         =   ""
      Enabled         =   False
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   571
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   False
      LockRight       =   True
      LockTop         =   True
      Scope           =   2
      TabIndex        =   4
      TabPanelIndex   =   0
      TabStop         =   True
      TextFont        =   "System"
      TextSize        =   15
      TextUnit        =   0
      Top             =   39
      Underline       =   ""
      Visible         =   True
      Width           =   22
   End
   Begin Label SeedLabel
      AutoDeactivate  =   True
      Bold            =   ""
      DataField       =   ""
      DataSource      =   ""
      Enabled         =   True
      Height          =   20
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   0
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Multiline       =   ""
      Scope           =   2
      Selectable      =   False
      TabIndex        =   6
      TabPanelIndex   =   0
      Text            =   "Salt:"
      TextAlign       =   2
      TextColor       =   0
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   39
      Transparent     =   False
      Underline       =   ""
      Visible         =   True
      Width           =   81
   End
   Begin PushButton GenBtn
      AutoDeactivate  =   True
      Bold            =   ""
      ButtonStyle     =   0
      Cancel          =   ""
      Caption         =   "Generate"
      Default         =   ""
      Enabled         =   True
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   140
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Scope           =   2
      TabIndex        =   0
      TabPanelIndex   =   0
      TabStop         =   True
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   71
      Underline       =   ""
      Visible         =   True
      Width           =   80
   End
   Begin PushButton OKBtn
      AutoDeactivate  =   True
      Bold            =   ""
      ButtonStyle     =   0
      Cancel          =   ""
      Caption         =   "OK"
      Default         =   ""
      Enabled         =   False
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   304
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Scope           =   2
      TabIndex        =   1
      TabPanelIndex   =   0
      TabStop         =   True
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   71
      Underline       =   ""
      Visible         =   True
      Width           =   80
   End
   Begin PushButton ExportBtn
      AutoDeactivate  =   True
      Bold            =   ""
      ButtonStyle     =   0
      Cancel          =   ""
      Caption         =   "Export"
      Default         =   ""
      Enabled         =   False
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   222
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Scope           =   2
      TabIndex        =   2
      TabPanelIndex   =   0
      TabStop         =   True
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   71
      Underline       =   ""
      Visible         =   True
      Width           =   80
   End
   Begin CheckBox UsePasswordChkbx
      AutoDeactivate  =   True
      Bold            =   ""
      Caption         =   "From password"
      DataField       =   ""
      DataSource      =   ""
      Enabled         =   True
      Height          =   20
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   20
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Scope           =   2
      State           =   0
      TabIndex        =   3
      TabPanelIndex   =   0
      TabStop         =   True
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   72
      Underline       =   ""
      Value           =   False
      Visible         =   True
      Width           =   110
   End
   Begin Thread GenThread
      Height          =   32
      Index           =   -2147483648
      Left            =   166
      LockedInPosition=   False
      Priority        =   5
      Scope           =   2
      StackSize       =   0
      TabPanelIndex   =   0
      Top             =   93
      Width           =   32
   End
   Begin Timer GenCompleteTimer
      Height          =   32
      Index           =   -2147483648
      Left            =   166
      LockedInPosition=   False
      Mode            =   0
      Period          =   1
      Scope           =   2
      TabPanelIndex   =   0
      Top             =   122
      Width           =   32
   End
   Begin PushButton CancelBtn
      AutoDeactivate  =   True
      Bold            =   ""
      ButtonStyle     =   0
      Cancel          =   True
      Caption         =   "Cancel"
      Default         =   ""
      Enabled         =   True
      Height          =   22
      HelpTag         =   ""
      Index           =   -2147483648
      InitialParent   =   ""
      Italic          =   ""
      Left            =   386
      LockBottom      =   ""
      LockedInPosition=   False
      LockLeft        =   True
      LockRight       =   ""
      LockTop         =   True
      Scope           =   2
      TabIndex        =   11
      TabPanelIndex   =   0
      TabStop         =   True
      TextFont        =   "System"
      TextSize        =   0
      TextUnit        =   0
      Top             =   71
      Underline       =   ""
      Visible         =   True
      Width           =   80
   End
End
#tag EndWindow

#tag WindowCode
	#tag Method, Flags = &h21
		Private Sub GenRandomSeed()
		  If UsePasswordChkbx.Value Then
		    mSeed = libsodium.Password.RandomSalt
		    SeedField.Text = libsodium.EncodeHex(mSeed)
		  Else
		    mSeed = Nil
		    SeedField.Text = ""
		  End If
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h0
		Function GetSecretKey() As libsodium.SKI.SecretKey
		  GenRandomSeed()
		  Me.ShowModal
		  Return mResult
		End Function
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub Show()
		  Super.Show()
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ShowModal()
		  Super.ShowModal
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ShowModalWithin(parentWindow As Window)
		  Super.ShowModalWithin(parentWindow)
		End Sub
	#tag EndMethod

	#tag Method, Flags = &h21
		Private Sub ShowWithin(parentWindow As Window, facing As Integer = - 1)
		  Super.ShowWithin(parentWindow, facing)
		End Sub
	#tag EndMethod


	#tag Property, Flags = &h21
		Private mPassword As libsodium.Password
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mResult As libsodium.SKI.SecretKey
	#tag EndProperty

	#tag Property, Flags = &h21
		Private mSeed As MemoryBlock
	#tag EndProperty


#tag EndWindowCode

#tag Events RndSeedBtn
	#tag Event
		Sub Action()
		  GenRandomSeed()
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events GenBtn
	#tag Event
		Sub Action()
		  If UsePasswordChkbx.Value Then
		    Dim pwdlg As New PasswordDialog
		    Dim p As libsodium.Password = pwdlg.GetPassword(mPassword)
		    If p = Nil Then Return
		    mPassword = p
		  End If
		  mResult = Nil
		  Me.Enabled = False
		  GenThread.Run()
		  
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events OKBtn
	#tag Event
		Sub Action()
		  Self.Close
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events ExportBtn
	#tag Event
		Sub Action()
		  If mResult = Nil Then Return
		  Dim f As FolderItem = GetSaveFolderItem(SodiumFileTypes.SecretKey, "secret.stk")
		  Dim pwdlg As New PasswordDialog
		  Dim p As libsodium.Password = pwdlg.GetPassword()
		  If Not mResult.Export(f, p) Then MsgBox("Export failed!")
		  
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events UsePasswordChkbx
	#tag Event
		Sub Action()
		  If Me.Value Then
		    SeedField.Enabled = True
		    RndSeedBtn.Enabled = True
		  Else
		    SeedField.Enabled = False
		    RndSeedBtn.Enabled = False
		  End If
		  GenRandomSeed()
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events GenThread
	#tag Event
		Sub Run()
		  If mPassword <> Nil Then ' from a Password
		    mResult = New libsodium.SKI.SecretKey(mPassword)
		    
		  Else ' random
		    mResult = libsodium.SKI.SecretKey.Generate()
		    
		  End If
		  
		  GenCompleteTimer.Mode = Timer.ModeSingle
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events GenCompleteTimer
	#tag Event
		Sub Action()
		  GenBtn.Enabled = True
		  OKBtn.Enabled = True
		  ExportBtn.Enabled = True
		  
		  If mResult <> Nil Then
		    PrivKeyLabel.Text = libsodium.EncodeHex(mResult.Value)
		  Else
		    PrivKeyLabel.Text = ""
		    OKBtn.Enabled = False
		    ExportBtn.Enabled = False
		    Call MsgBox("Key generation failed.", 16, "Error")
		    
		  End If
		End Sub
	#tag EndEvent
#tag EndEvents
#tag Events CancelBtn
	#tag Event
		Sub Action()
		  mResult = Nil
		  Self.Close
		End Sub
	#tag EndEvent
#tag EndEvents
