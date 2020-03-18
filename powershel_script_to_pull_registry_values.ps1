$hostname=hostname
$ErrorActionPreference= 'silentlycontinue'
$Pazh = "C:\$hostname.txt"
Start-Transcript -Path $Pazh -NoClobber


Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\"| fl EnableScriptBlockLogging

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"  | fl CachedLogonsCount

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"  | fl ForceUnlockLogon

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"  | fl PasswordExpiryWarning

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"  | fl ScRemoveOption

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"| fl  CachedLogonsCount

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"| fl AllocateDASD

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"| fl AutoAdminLogon

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"| fl PasswordExpiryWarning

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"| fl ScreenSaverGracePeriod

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\"| fl SCRemoveOption

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\"| fl HideZoneInfoOnProperties

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\"| fl SaveZoneInformation

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\"| fl ScanWithAntiVirus

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\"| fl EnumerateAdministrators

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"| fl NoAutorun

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\"| fl NoDriveTypeAutoRun

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"| fl NoInPlaceSharing

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"| fl NoInternetOpenWith

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\"| fl PreXPSP2ShellProtocolBehavior

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\"| fl UseWindowsUpdate

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"| fl MSAOptional

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl ConsentPromptBehaviorAdmin

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl ConsentPromptBehaviorUser

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl DontDisplayLastUserName

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl EnableInstallerDetection

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl EnableLUA

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl EnableSecureUIAPaths

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl EnableUIADesktopToggle

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl EnableVirtualization

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl LegalNoticeCaption

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl LegalNoticeText

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl PromptOnSecureDesktop

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl ShutdownWithoutLogon

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl UndockWithoutLogon

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"  | fl ValidateAdminCodeSignatures

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl  LogonType

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl ConsentPromptBehaviorAdmin

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl ConsentPromptBehaviorUser

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl DisableAutomaticRestartSignOn

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\system\"| fl DisableBkGndGroupPolicy

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl DisableCAD

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl DontDisplayLastUserName

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl EnableInstallerDetection

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl EnableLUA

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl EnableSecureUIAPaths

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl EnableUIADesktopToggle

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl EnableVirtualization

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl FilterAdministratorToken

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl InactivityTimeoutSecs

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl LegalNoticeCaption

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl LegalNoticeText

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl LocalAccountTokenFilterPolicy

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl PromptOnSecureDesktop

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl ShutdownWithoutLogon

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\"| fl ValidateAdminCodeSignatures

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\"| fl ProcessCreationIncludeCmdLine_Enabled

Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\"| fl SupportedEncryptionTypes

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\"| fl NoExplicitFeedback

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Assistance\Client\1.0\"| fl NoImplicitFeedback

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Biometrics\"| fl Enabled

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Control Panel\International\"| fl BlockUserInputMethodsForSignIn

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Cryptography\"| fl  ForceKeyProtection

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\EventViewer\"| fl MicrosoftEventVwrDisableLinks

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\"| fl AllowBasicAuthInClear

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\"| fl DisableEnclosureDownload

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Peernet\"| fl Disabled

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"| fl ACSettingIndex

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\"| fl DCSettingIndex

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows\"| fl CEIPEnable

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\SpyNet\"| fl  SpyNetReporting

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\"| fl DisableHTTPPrinting

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\"| fl DisableWebPnPDownload

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\"| fl DoNotInstallCompatibleDriverFromWindowsUpdate

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\"| fl  RestrictRemoteClients

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\ "| fl fAllowToGetHelp

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\ "| fl fSingleSessionPerUser 

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl DeleteTempDirsOnExit

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl DisablePasswordSaving

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fAllowUnsolicited

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fDisableCcm

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fDisableCdm

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fDisableLPT

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fDisablePNPRedir

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fEnableSmartCard

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fEncryptRPCTraffic

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl fPromptForPassword

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl LoggingEnabled

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl MinEncryptionLevel

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl PerSessionTempDir

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\"| fl RedirectOnlyDefaultClientPrinter

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat\"| fl DisableInventory

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppCompat\"| fl DisablePcaUI

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Appx\"| fl AllowAllTrustedApps

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\"| fl ScreenSaveActive

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop\"| fl ScreenSaverIsSecure

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CredUI\"| fl DisablePasswordReveal

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"| fl NoCloudApplicationNotification

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\"| fl NoToastApplicationNotificationOnLockScreen

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Device Metadata\"| fl  PreventDeviceMetadataFromNetwork

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\"| fl AllowRemoteRPC

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\"| fl DisableSendGenericDriverNotFoundToWER

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\"| fl DisableSendRequestAdditionalSoftwareToWER

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings\"| fl DisableSystemRestore

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching\"| fl DontPromptForWindowsUpdate

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching\"| fl DontSearchWindowsUpdate

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching\"| fl DriverServerSelection

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DriverSearching\"| fl SearchOrderConfig

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\"| fl MaxSize

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\"| fl MaxSize

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\Setup\"| fl MaxSize

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\"| fl MaxSize

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer\"| fl NoAutoplayfornonVolume

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer\"| fl NoDataExecutionPrevention

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer\"| fl NoHeapTerminationOnCorruption

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer\"| fl NoUseStoreOpenWith

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\"| fl NoGPOListChanges

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\HandwritingErrorReports\"| fl PreventHandwritingErrorReports

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\"| fl AlwaysInstallElevated

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\"| fl DisableLUAPatching

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\"| fl EnableUserControl

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer\"| fl SafeForScripting

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD\"| fl AllowLLTDIOOndomain, AllowLLTDIOOnPublicNet, EnableLLTDIO, ProhibitLLTDIOOnPrivateNet

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LLTD\"| fl AllowRspndrOndomain, AllowRspndrOnPublicNet, EnableRspndr, ProhibitRspndrOnPrivateNet

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors\"| fl DisableLocation

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\"| fl NC_AllowNetBridge_NLA

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Network Connections\"| fl NC_StdDomainUserSetLocation

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Personalization\"| fl NoLockScreenSlideshow

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\"  | fl AuthenticodeEnabled

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\"| fl DisableQueryRemoteServer

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\"| fl EnableQueryRemoteServer

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\"| fl DisableLockScreenAppNotifications

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\"| fl DontDisplayNetworkSelectionUI

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\"| fl EnableSmartScreen

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System\"| fl EnumerateLocalUsers

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\"| fl 6to4_State

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\"| fl Force_Tunneling

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\"| fl ISATAP_State

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\"| fl Teredo_State

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface\"| fl IPHTTPS_ClientState

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\Registrars\"| fl DisableFlashConfigRegistrar, DisableInBand802DOT11Registrar, DisableUPnPRegistrar, DisableWPDRegistrar, EnableRegistrars

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WCN\UI\"| fl DisableWcnUi

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\"| fl ScenarioExecutionEnabled

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\"| fl AllowBasic

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\"| fl AllowDigest

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\"| fl AllowUnencryptedTraffic

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\"| fl AllowBasic

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\"| fl AllowUnencryptedTraffic

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\"| fl DisableRunAs

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\"| fl DisableAutoupdate

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\"| fl GroupPrivacyAcceptance

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer\"| fl PreventCodecDownload

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore\"| fl  AutoDownload

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore\"| fl  RemoveWindowsStore

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore\WindowsUpdate\"| fl  AutoDownload

Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM\"| fl DisableOnline

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl AuditBaseObjects

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl CrashOnAuditFail

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl DisableDomainCreds

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl EveryoneIncludesAnonymous

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl ForceGuest

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl FullPrivilegeAuditing

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl LimitBlankPasswordUse

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl NoLMHash

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl RestrictAnonymous

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl RestrictAnonymous

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl RestrictAnonymousSAM

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"  | fl SCENoApplyLegacyAuditPolicy

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl AuditBaseObjects

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl DisableDomainCreds

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl EveryoneIncludesAnonymous

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl ForceGuest

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl FullPrivilegeAuditing

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl LimitBlankPasswordUse

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl LmCompatibilityLevel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl NoLMHash

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl RestrictAnonymousSAM

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\"| fl SCENoApplyLegacyAuditPolicy

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\"| fl UseMachineId

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"  | fl Enabled

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"| fl Enabled

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\"  | fl NTLMMinClientSec

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\"  | fl NTLMMinServerSec

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0\"| fl allowNonesessionfallback

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\"| fl NTLMMinClientSec

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\"| fl NTLMMinServerSec

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\pku2u\"| fl AllowOnlineID

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\"  | fl AddPrinterDrivers

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\"| fl AddPrinterDrivers

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\" | fl CurrentVersion

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\"| fl Machine

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\" | fl SysmonLog

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\"| fl Machine

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\SecurityProviders\Wdigest\"| fl UseLogonCredential

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\"  | fl ProtectionMode

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\"| fl ProtectionMode

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\"| fl SafeDllSearchMode

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel\"  | fl ObCaseInsensitive

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel\"| fl ObCaseInsensitive

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management\"  | fl ClearPageFileAtShutdown

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\SubSystems\"  | fl optional

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Subsystems\"| fl Optional

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Policies\EarlyLaunch\"| fl DriverLoadPolicy

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Eventlog\Security\"| fl WarningLevel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\IPSEC\"| fl NoDefaultExempt

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"  | fl EnableForcedLogOff

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"  | fl EnableSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"  | fl NullSessionPipes

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"  | fl RequireSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"  | fl RestrictNullSessAccess

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl  autodisconnect

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl EnableForcedLogoff

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl EnableSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl NoneSessionPipes

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl NoneSessionShares

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl RequireSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\"| fl RestrictNoneSessAccess

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\"| fl SMB1

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\"| fl SmbServerNameHardeningLevel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\"| fl DependOnService

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\"  | fl EnablePlainTextPassword

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\"  | fl EnableSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\"  | fl RequireSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\"| fl  EnablePlainTextPassword

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\"| fl EnableSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\"| fl RequireSecuritySignature

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LDAP\"  | fl LDAPClientIntegrity

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LDAP\"| fl LDAPClientIntegrity

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\mrxsmb10\"| fl Start

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\"| fl  NoNameReleaseOnDemand

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"  | fl DisablePasswordChange

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"  | fl MaximumPasswordAge

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"  | fl RequireSignOrSeal

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"  | fl RequireStrongKey

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"  | fl SealSecureChannel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"  | fl SignSecureChannel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"| fl DisablePasswordChange

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"| fl MaximumPasswordAge

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"| fl RequireSignOrSeal

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"| fl RequireStrongKey

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"| fl SealSecureChannel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\"| fl SignSecureChannel

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"| fl  TcpMaxDataRetransmissions

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"| fl DisableIPSourceRouting

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"| fl EnableICMPRedirect

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"| fl EnableIPAutoConfigurationLimits

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"| fl KeepAliveTime

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\"| fl PerformRouterDiscovery

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\"| fl  TcpMaxDataRetransmissions

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\"| fl DisableIPSourceRouting


Stop-Transcript
