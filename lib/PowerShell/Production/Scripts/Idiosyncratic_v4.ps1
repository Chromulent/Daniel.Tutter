########################################################################################################################
<##
Information:
Windows Workstation Configuration.

Function:
Automate initial workstation configuration tasks that should be performed by a script.

Written by:
Daniel James Harrison Tutter

Date:
12023.03.11

Version 3.1.2
##>
########################################################################################################################

#=====[  ]=====#

# Define Title
$host.ui.RawUI.WindowTitle = "Idiosyncratic"

#   Define that we are using Windows Script Shell to send keys to the title of the program; automating the Execution Policy.
    $shell = New-Object -ComObject Wscript.Shell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned | echo $shell.sendkeys("Y`r`n")
    $enterwshell = New-Object -ComObject wscript.shell;
    $enterwshell.AppActivate('Idiosyncratic')
    Sleep 1
    $enterwshell.SendKeys('~')


# If the script is not running in an elevated shell then it will attempt to run another elevated shell and run commands from this script into the buffer and load it into the elevated shell.
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))  
{  
    $arguments = "& '" +$myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

#=====[ Create Directories ]=====#
########################################################################################################################
    New-Item -Path "C:\" -Name "temp" -ItemType "directory"  -EA SilentlyContinue
    New-Item -Path "C:\" -Name "Automation" -ItemType "directory"  -EA SilentlyContinue
    Set-Location -Path "C:\temp"

# Create Restore Point before letting the script make changes.
    Write-Host('Creating Restore Point...') -Fore White
    Enable-ComputerRestore -Drive "C:\"
    $time = (Get-Date).ToString("yyyy:MM:dd")
    Checkpoint-Computer -Description $time -RestorePointType "MODIFY_SETTINGS"   
    
# Rename Computer
    $NewComputerName = Read-Host -Prompt 'What is the name of this machine going to be?'

########################################################################################################################
#=====[ RegKey Modifications ]=====#
########################################################################################################################

# ================ Login ================
# Disable first time logon animation
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name 'EnableFirstLogonAnimation' -PropertyType DWORD -Value 0 -Force -EA SilentlyContinue
# Disable the New Lock Screen and Disables the shade up effects
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Disable Users On Login Screen
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Type DWord -Value  1 
# Disable Lockscreen suggestions, rotating pictures
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "SoftLandingEnabled" -Value 0 -Force -EA SilentlyContinue -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "RotatingLockScreenEnabled" -Value 0 -Force -EA SilentlyContinue -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "RotatingLockScreenOverlayEnabled" -Value 0 -Force -EA SilentlyContinue -EA SilentlyContinue 
#Disallow Cortana on lock screen
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Type DWord "AllowCortanaAboveLock" -Value 0 -Force -EA SilentlyContinue 

# ================ Explorer / General ================
# Disable Activity History and Timeline
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Show File Operation Details
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Change Default View to this PC
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Disable 3D Objects Icon
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace" -Name "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -EA SilentlyContinue
# Disable History View
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Type DWord -Value  0 -Force -EA SilentlyContinue
<# # Remove Downloads library from My PC
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{088e3905-0323-4b02-9826-5d99428e115f}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{374DE290-123F-4565-9164-39C4925E467B}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{088e3905-0323-4b02-9826-5d99428e115f}" -Force
# Remove Pictures library from My PC
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Force
# Remove Music library from My PC
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Force
# Remove Desktop library from My PC
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Force
# Remove Documents library from My PC
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{d3162b92-9365-467a-956b-92703aca08af}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{d3162b92-9365-467a-956b-92703aca08af}" -Force
# Remove Videos library from My PC
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Force
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Force #>
# Remove 3D Objects library from My PC
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -EA SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace"  -Name "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -EA SilentlyContinue
# Removes the shake to minimize all other windows getures
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value  1 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value  1 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value  1 
    Remove-Item -Path "HKEY_CLASSES_ROOT\CABFolder\CLSID" -EA SilentlyContinue
    Remove-Item -Path "HKEY_CLASSES_ROOT\SystemFileAssociations\.cab\CLSID" -EA SilentlyContinue
    Remove-Item -Path "HKEY_CLASSES_ROOT\CompressedFolder\CLSID" -EA SilentlyContinue
    Remove-Item -Path "HKEY_CLASSES_ROOT\SystemFileAssociations\.zip\CLSID" -EA SilentlyContinue
# Remove OneDrive from the Explorer Side Panel
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value  0
# Show hidden files in Windows Explorer
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Remove the Open with Paint 3D from the explorer context menu
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit"  -Force -EA SilentlyContinue
# Removes Paint3D from the context menu
    Remove-Item -Path "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.png\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"  -Force -EA SilentlyContinue
    Remove-Item -Path "HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"  -Force -EA SilentlyContinue
# Remove Edit with Paint 3D from context menu
    Remove-Item -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit"  -Force -EA SilentlyContinue
# Do not track most used apps
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackProgs" -Type DWord -Value 0 -Force -EA SilentlyContinuex00000000 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Type DWord -Value 0 -Force -EA SilentlyContinuex00000000 -Force
# Show File Extensions
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable Sticky Keys
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 127 -Force -EA SilentlyContinue
#Enable Sticky Keys 
  # Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 510 -Force -EA SilentlyContinue
# ================ Explorer / Advanced ================
# Disable UAC
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "EnableLUA" -PropertyType DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable Info bar prompting that Windows Search has been disasbled
    Set-ItemProperty -Path "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "InfoBarsDisabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" 
# Disable Ads in File Explorer
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Type DWord "ShowSyncProviderNotifications" -Value 0 -Force -EA SilentlyContinue 
# Add "Run as different user" to context menu
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -EA SilentlyContinue 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowRunasDifferentuserinStart"  -Type DWord -Value 1 -Force -EA SilentlyContinue 
# Show Full Path in the address bar
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPathAddress" -Type DWord -Value 1 -Force -EA SilentlyContinue

# ================ Privacy ================
# Remove all content from auto logger Diagnostic Tracker
Add-Content -Path 'C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl' -Value '' -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener"  -Name "Start" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\InfoBarsDisabled" "LocationNotIndexed"  -Type DWord -Value 1 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\InfoBarsDisabled" "ServerMSSNotInstalled"  -Type DWord -Value 1 -Force -EA SilentlyContinue
# Disable Telemetry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable Location Tracking - global
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable CEIP
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient'
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows'
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name "CEIPEnable" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable Antispyware
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWORD  -Value 1 -Force -EA SilentlyContinue
# Remove SecurityHealth from startup
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "SecurityHealth" -Force
# Turns off Windows blocking installation of files downloaded from the internet
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value  1 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value  1 -Force
# Turn Off Microsoft Defender SmartScreen for Microsoft Store Apps in Windows 10
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable SmartScreen
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off" -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "ContentEvaluation" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Do not accept the policy
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Enable diagnostic data viewer
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" -Type DWord "EnableEventTranscript" -Value 1 -Force -EA SilentlyContinue

# ================ Application ================
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name CloudContent -EA SilentlyContinue
# Disable services that are known to cause issues
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type String -Value "%windir%\System32\taskkill.exe" -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop"  -Name "AutoEndTasks" -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\xboxgip"  -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\XboxGipSvc"  -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\CDPUserSvc"  -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\UnistoreSvc" -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\UserDataSvc" -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\XblGameSave"  -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\WpnUserService" -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\XboxNetApiSvc"  -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\XblAuthManager"  -Name "Start" -Value 4 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" -Name "Start" -Value 4 -Force -EA SilentlyContinue
    New-Item -Path "HKLM:\SYSTEM\ControlSet001\Control\WMI" -Name "AutoLogger" -Force -EA SilentlyContinue
# Disable application suggestions
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable 'Get tips, tricks, suggestions as you use Windows'
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Type DWord "DisableWindowsSpotlightFeatures" -Value 1 -Force -EA SilentlyContinue
# Microsoft pushing applications quietly into your profile
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "SubscribedContentEnabled" -Value 0 -Force -EA SilentlyContinue
# Disable automatic maps update
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable background application access
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
    Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1 -Force -EA SilentlyContinue
    Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1 -Force -EA SilentlyContinue}
# Turn Off OneDrive
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWord -Value 1 -Force -EA SilentlyContinue 
# Remove Background Tasks
    Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
# Remove Background Tasks Windows Files
    Remove-Item "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" 
#Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
#Scheduled Tasks to delete
    Remove-Item "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" -Recurse -ErrorAction SilentlyContinue
#Windows Protocol Keys
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
    Remove-Item "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy" -Recurse -ErrorAction SilentlyContinue
#Windows Share Target
    Remove-Item "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" -Recurse -ErrorAction SilentlyContinue
# Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings
    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic' -Name 'FirstRunSucceeded' -Value 0 -Force -EA SilentlyContinue -Verbose
# Preinstalled apps, Minecraft Twitter etc all that - still need a clean default start menu to fully eliminate
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "PreInstalledAppsEnabled" -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "PreInstalledAppsEverEnabled" -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "OEMPreInstalledAppsEnabled" -Value 0 -Force -EA SilentlyContinue 
# Disable Xbox Game DVR
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Type DWord "GameDVR_Enabled" -Value 0 -Force -EA SilentlyContinue 
# Disable OneDrive startup run user settings
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /T REG_BINARY /V "OneDrive" -Value 0 -Force -EA SilentlyContinue300000021B9DEB396D7D001 
# Disable automatic OneDrive desktop setup for     New accounts
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force -EA SilentlyContinue
# Disable Game Monitoring Service
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm" -Type DWord "Start" -Value 4 -Force -EA SilentlyContinue
# GameDVR local GP - Computer Config\Admin Templates\Windows Components\Windows Game Recording and Broadcasting
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Type DWord "AllowGameDVR" -Value 0 -Force -EA SilentlyContinue 
# Brave - Presets
New-Item -Path "HKLM:\Software\Policies\BraveSoftware" -EA SilentlyContinue 
New-Item -Path "HKLM:\Software\Policies\BraveSoftware\Brave" -EA SilentlyContinue 
New-Item -Path "HKLM:\Software\Policies\BraveSoftware\Brave\Recommended" -EA SilentlyContinue 
# Brave - Disable Saving Passwords HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\BraveSoftware\Brave" -Name "PasswordManagerEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Brave - Disable AutoFill for credit cards HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\BraveSoftware\Brave\Recommended" -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Brave - Turn off Background mode HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\BraveSoftware\Brave\Recommended" -Name "BackgroundModeEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Brave - Enable set Brave as default Browser HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\BraveSoftware\Brave" -Name "DefaultBrowserSettingEnabled" -Type DWord -Value 1 -Force -EA SilentlyContinue 
# Brave - Enable Bookmark Bar HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\BraveSoftware\Brave" -Name "BookmarkBarEnabled" -Type DWord -Value 1 -Force -EA SilentlyContinue 
# Chrome - Presets
New-Item -Path "HKLM:\Software\Policies\Google" -EA SilentlyContinue 
New-Item -Path "HKLM:\Software\Policies\Google\Chrome" -EA SilentlyContinue 
New-Item -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -EA SilentlyContinue 
# Chrome - Disable Saving Passwords HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "PasswordManagerEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Chrome - Disable AutoFill for credit cards HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Chrome - Turn off Background mode HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -Name "BackgroundModeEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Chrome - Disable set Chrome as default Browser HKLM 
New-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "DefaultBrowserSettingEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Chrome - Enable Bookmark Bar HKLM
New-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "BookmarkBarEnabled" -Type DWord -Value 1 -Force -EA SilentlyContinue 

# ================ Internet Explorer / Microsoft Edge ================
# Disable Internet Explorer first time run start requirements
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2 -Force -EA SilentlyContinue
# Disable Microsoft Edge first time run start requirements
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "MicrosoftEdge"
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Name "Main"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Type DWord  -Name AllowPrelaunch -Value 0 -Force -EA SilentlyContinue
        reg load HKLM\Default_User C:\Users\Default\NTUSER.DAT
# Do not track - Edge
    New-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" -Type DWord "DoNotTrack" -Value 1 -Force -EA SilentlyContinue 
# Do not track - IE
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main" -Type DWord "DoNotTrack" -Value 1 -Force -EA SilentlyContinue 
# Disable Edge desktop shortcut
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Type DWord "DisableEdgeDesktopShortcutCreation" -Value 1 -Force -EA SilentlyContinue 

# ================ Search / Cortana ================
# Disable Windows Search
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null -EA SilentlyContinue
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null -EA SilentlyContinue
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null -EA SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"  -Name "AllowCortana" -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Dont Search the web or display web results
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWeb" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Dont allow search to use location
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Disable Search Suggestions
    New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value  1 
# Disable Voice Activation
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationDefaultOn" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -Type DWord -Value  1 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "ModelDownloadAllowed" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Disable Voice Activation at lockscreen
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences" -Name "VoiceActivationEnableAboveLockscreen" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Do not allow indexing on Encrypted Store or Items
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Disable SafeSearch in the search menu
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearchMode" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Disable other Search settings
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AlwaysUseAutoLangDetection" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "HasAboveLockTips" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "ConnectedSearchUseWebOverMeteredConnections" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Type DWord -Value 0 -Force -EA SilentlyContinue 

# ================ Start Menu ================
# Disable Bing search
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Disable Cortana in ambient mode
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaInAmbientMode" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Disable live tiles
    New-Item -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -EA SilentlyContinue 
    New-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoTileApplicationNotification' -Type DWord -Value 1 -Force -EA SilentlyContinue 
# Removing CloudStore
    Remove-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore' -Recurse -Force
# Disable Cortana
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Type DWord "CortanaEnabled" -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Type DWord "CanCortanaBeEnabled" -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Type DWord "DeviceHistoryEnabled" -Value 0 -Force -EA SilentlyContinue 
# Disable Tiles
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen" -Name "TileMigrated" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Change Start Menu Speed
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name MenuShowDelay -Value 20 -Force -EA SilentlyContinue
# Change Time to Holocene
    New-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sTimeFormat" -Type String -Value "HH:mm:ss" -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortTime" -Type String -Value "HH:mm" -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sLongDate" -Type String -Value "dddd, dd MMMM, 1yyyy" -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\Control Panel\International" -Name "sShortDate" -Type String -Value "dd-MMM-1yyyy" -Force -EA SilentlyContinue

# ================ Task Manager ================
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
# Always show all tray Icons in windows
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0 -Force -EA SilentlyContinue

# ================ Taskbar  ================
# Hide Task View Button
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Hide People Icon
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null -EA SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable Taskbar or Search box
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable action center
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null -EA SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 -Force -EA SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Dont show My People notifications
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People\ShoulderTap" -Type DWord "ShoulderTap" -Value 0 -Force -EA SilentlyContinue 
# Disable "Meet Now" taskbar button
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Type DWord "HideSCAMeetNow" -Value 1 -Force -EA SilentlyContinue 
# Enable Small icons
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Group Windows - Always combine
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Hide Cortana on the Task bar
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable News and Interests
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2 -Force -EA SilentlyContinue

# ================ Microsoft Feedback ================
# Disable Microsoft Consumer Experience
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name CloudContent -EA SilentlyContinue
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -name 'DisableWindowsConsumerFeatures' -PropertyType DWORD -Value 1 -Force -EA SilentlyContinue
# Disable feedback
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf" -Force | Out-Null -EA SilentlyContinue
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null -EA SilentlyContinue
    New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds" -Force | Out-Null -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 -Force -EA SilentlyContinue
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Siuf\Rules' -Name "NumberOfSIUFInPeriod" -PropertyType DWord -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds' -Name 'PeriodInNanoSeconds' -PropertyType DWord -Value 0 -Force -EA SilentlyContinue -Verbose
# Disable tailored feedback
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null -EA SilentlyContinue
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Disable advertising ID
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null -EA SilentlyContinue
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0 -Force -EA SilentlyContinue -Verbose
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value  1 
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"  -Name "Device Metadata" -Force
# Disable error reporting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Disable Remote Assitance
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable Storage Sense
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
# Disable Creation of Crash Dumps that are sent to Microsoft
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Disable File Samples to Analysis
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
# Disable System Settings Sync
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Type DWord -Value  2 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSyncUserOverride" -Type DWord -Value  1 -Force
# Do not automatically encrypt files moved to encrypted folders
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" -Name "TCGSecurityActivationDisabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Do not uese Certificate Rules on Windows Executables for Software Restriction Policies
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" -Name "authenticodeenabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Do not send Error Reporting Additional Data 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type DWord -Value 1 -Force -EA SilentlyContinue
# Restrict Handwriting information being sent to Microsoft
    New-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value  1  -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value  1  -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Disable Tailored experiences - Diagnostics & Feedback settings
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Type DWord "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Force -EA SilentlyContinue 
# Speech language sync
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Type DWord "Enabled" -Value 0 -Force -EA SilentlyContinue 
# Do not improve inking & typing recognition
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Type DWord "Enabled" -Value 0 -Force -EA SilentlyContinue 
# Pen & Windows Ink - Show recommended app suggestions
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Type DWord "PenWorkspaceAppSuggestionsEnabled" -Value 0 -Force -EA SilentlyContinue 
# Do not Show My People app suggestions
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "SubscribedContent-314563Enabled" -Value 0 -Force -EA SilentlyContinue 
# Turn off Computer Maintenance (System Maintenance) (Determines whether scheduled diagnostics will run to proactively detect and resolve system problems.)
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" -Name "EnabledExecution" -Type DWord -Value 0 -Force -EA SilentlyContinue

# ================ Power Settings ================
# Disable Hibernation
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0 -Force -EA SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0 -Force -EA SilentlyContinue

# ================ Control Panel ================
# Dont show suggested content in settings
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"  -Type Dword -Name  "SubscribedContent-338393Enabled" -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"  -Type Dword -Name  "SubscribedContent-353694Enabled" -Value 0 -Force -EA SilentlyContinue
# Do Not Show suggestions occasionally
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"  -Type Dword -Name  "SubscribedContent-338388Enabled" -Value 0 -Force -EA SilentlyContinue
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "controlpanel"
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\controlpanel" -Name "StartupPage" -Type DWord -Value  1 -Force -EA SilentlyContinue
# Set Icons in Control Panel to small
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\controlpanel" -Name "AllItemsIconView" -Type DWord -Value  1 -Force -EA SilentlyContinue

# ================ Personalization ================
# Enable Darkmode
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Force -EA SilentlyContinue
# Disable phone pairing
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Type DWord "UserAuthPolicy" -Value 0 -Force -EA SilentlyContinue 
# Decrease Shutdown time
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeOut" -Type String -Value "2000" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type String -Value "2000" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "HungAppTimeout" -Type String -Value "2000" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "AutoEndTasks" -Type String -Value "1" -Force -EA SilentlyContinue 
# Disable "Let Windows Fix Blurry Apps" Automatically Option
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "EnablePerProcessSystemDPI" -Type Dword -Value "0" -Force -EA SilentlyContinue 
# Set Display Scaling to 100%
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type Dword -Value "96" -Force -EA SilentlyContinue 
# This lets you set custom scaling and is tied to the above LogPixels regedit. If any other value other than 96, set to 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type Dword -Value "0" -Force -EA SilentlyContinue
# Set scaling to small for all displays
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DesktopDPIOverride" -Type Dword -Value "0" -Force -EA SilentlyContinue

# ================ Network ================
# Disable IPv6
    Set-NetAdapterBinding -Name Ether* -ComponentID ms_tcpip6 -Enabled $false  -EA SilentlyContinue 
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' -Name "DisabledComponents" -Type DWord -Value "ff" -Force -EA SilentlyContinue 
# Disable the Network Location Wizard
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\Network" -Name "NewNetworkWindowOff"  -EA SilentlyContinue 
# Do not Allow Wifi to AutoConnect to Known Wifi Networks
    New-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "value" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Firewall rules to prevent the startmenu from communiacating
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "Block Search SearchApp.exe" -Type String -Value 'v2.30|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|App=C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe|Name=Block Search SearchUI.exe|Desc=Block Cortana Outbound UDP/TCP Traffic|' -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -Name "Block Search Package" -Type String -Value 'v2.30|Action=Block|Active=TRUE|Dir=Out|RA42=IntErnet|RA62=IntErnet|Name=Block Search Package|Desc=Block Search Outbound UDP/TCP Traffic|AppPkgId=S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757|Platform=2:6:2|Platform2=GTEQ|' -Force -EA SilentlyContinue 
# Disable active probing to Microsoft Network Connectivity Status Indicator
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Type DWord -Value  1 -Force -EA SilentlyContinue 
## Disable Windows Firewall, for all Network Profiles ##
# Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
# TCP/IP Task Offload - Disable (TCP/IP Task Offload.) (Transfers the workload from the CPU to the NIC, during data transfers.) (aka checksum offloading)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" -Name "DisableTaskOffload" -Type DWord -Value  1 -Force -EA SilentlyContinue 

# ================ Windows Updates ================
# Restrict Windows Update P2P only on the local network
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "Config" -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Type DWord -Value 0 -Force -EA SilentlyContinue 
# Do not show me the Windows welcome experience after updates and occasionally
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Type DWord "SubscribedContent-310093Enabled" -Value 0 -Force -EA SilentlyContinue 
# Turn off featured SOFTWARE notifications through Windows Update
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Type DWord "EnableFeaturedSoftware" -Value 0 -Force -EA SilentlyContinue 
# Delivery Optimization Settings
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Type DWord "DownloadMode" -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Type DWord "DODownloadMode" -Value 0 -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" -Type DWord "DownloadMode" -Value 0 -Force -EA SilentlyContinue 
# Turn off automatic download/install of store app updates
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "WindowsStore" -EA SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore" -Name "WindowsUpdate" -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Type DWord "AutoDownload" -Value 2 -Force -EA SilentlyContinue
# Prevent using sign-in info to automatically finish setting up after an update
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Type DWord "ARSOUserConsent" -Value 0 -Force -EA SilentlyContinue 
# Set automatic updates to download and intsall automatically
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -EA SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Value 3 -Force -EA SilentlyContinue 
# Disable Automatic Updates and re-install of pre-installed bloatware
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "WindowsStore" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value  2 -Force -EA SilentlyContinue      #disable
#    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value  4 -Force -EA SilentlyContinue       #enable
    New-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value  1 -Force
    New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value  1 -Force
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseActionCenterExperience" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAHealth" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value  1 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 -Force -EA SilentlyContinue
# Enable driver offerings through Windows Update.
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
# Disable automatic restart
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
# Set automatic updates to not download and intsall automatically.
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate" -ErrorAction SilentlyContinue
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU" -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name AUOptions -Value 3 -ErrorAction SilentlyContinue

########################################################################################################################
#=====[ Services ]=====#
########################################################################################################################

# Disable Service Known to cause issues
$Services = @(
# unnecessary services
"sysmain"
"WpnService"
"WSearch"
"DiagTrack"
"diagnosticshub.standardcollector.service"
"ClicktoRunSvc"
"dmwappushservice"
"HomeGroupListener"
"HomeGroupProvider"
"RetailDemo"
"lfsvc"
"MapsBroker"
"OneSyncSvc"
"XblAuthManager"
"XblGameSave"
"XboxNetApiSvc"
"WerSvc"
)

foreach ($Service in $Services) {
Set-Service -Name $Service -StartupType Disabled -EA SilentlyContinue
Write-Host "Setting $Service to disabled."

Stop-Service -Name $Service -Force -Confirm:$false -EA SilentlyContinue
Write-Host "Stopping $Service..."

}

#Disabling the Diagnostics Tracking Service
cmd /c sc delete DiagTrack -EA SilentlyContinue
cmd /c sc delete dmwappushservice -EA SilentlyContinue
cmd /c sc delete diagnosticshub.standardcollector.service -EA SilentlyContinue

#  Ensure Windows Update services are started properly.
$UpdateServices= @(

# Update Services
"wuauserv"
"bits"


)
foreach ($UpdateService in $UpdateServices) {
Stop-Service -Name $UpdateService -Force -Confirm:$false -EA SilentlyContinue
Write-Host "Stopping $UpdateService..."

Set-Service -Name $UpdateService -StartupType Automatic 
Write-Host "Setting $UpdateService to automatic."

Start-Service  -Name $UpdateService
Write-Host "Starting $UpdateService..."}

### Kill Windows Search UI
Stop-Process -Name "SearchUi.exe" -Force -EA SilentlyContinue
$Currentlocation = (Get-Location).path
cd $env:windir\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy
takeown /f SearchUI.exe
icacls SearchUI.exe /grant administrators:F
Stop-Process -Name "SearchUi.exe" -Force -EA SilentlyContinue
cmd /c rename SearchUI.exe SearchUI.exe.001
cd $Currentlocation

########################################################################################################################
#=====[ Software ]=====#
########################################################################################################################

#=====[ Software Configuration ]=====#
#Stops edge from taking over as the default .PDF viewer
Write-Host('Stopping Edge from taking over as the default .PDF viewer') -Fore White
# Identify the edge application class
$Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
$edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge"

# Specify the paths to the file and URL associations
$FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations
$URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations

# get the software classes for the file and URL types that Edge will associate
$FileTypes = Get-Item $FileAssocKey
$URLTypes = Get-Item $URLAssocKey

$FileAssoc = Get-ItemProperty $FileAssocKey
$URLAssoc = Get-ItemProperty $URLAssocKey

$Associations = @()
$Filetypes.Property | foreach {$Associations += $FileAssoc.$_}
$URLTypes.Property | foreach {$Associations += $URLAssoc.$_}

# add registry values in each software class to stop edge from associating as the default
foreach ($Association in $Associations)
        {
    $Class = Join-Path HKCU:SOFTWARE\Classes $Association
    #if (Test-Path $class)
    #   {write-host $Association}
    # Get-Item $Class
    Set-ItemProperty $Class -Name NoOpenWith -Value ""
    Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value ""
        }


Set-Content -Path 'C:\Automation\Choco.ps1' -Value {
    # Zoom Download and Install
    # choco install zoom -y
    # Brave Download
    winget install "Brave Browser"
    winget install "Sublime Text 4"
    winget install "ShareX"
    winget install "Valve.Steam" --source winget
    winget install "Windows Terminal" --source msstore
    winget install "Discord.Discord"
    winget install "Google.Chrome"
    winget install "VSCodium.VSCodium"
    winget install "Megasync"
    winget install "Windows Subsystem for Linux"
    winget install "Okular" --source msstore
    winget install "ImageGlass"
    winget install "mpv.net"
    winget install "Notepad++"
    winget install "Notion.Notion"
    winget install "RoyalTS"
    winget install "Logitech Unifying Software"
    winget install "Mullvad VPN"
    winget install "Git.Git"
    winget install "Github Desktop"
    winget install "UltraVNC"
    winget install "Mojang.MinecraftLauncher"
    winget install "startallback"



    # Set Brave and Chrome Extensions for use
    Set-Location -Path "C:\Users\Default\Links"
    $URLs = @(

        "https://www.mediafire.com/file/x3d7jl3i6sqqnmm/BitWarden_extension_1_56_4_0.crx/file"
        "https://www.mediafire.com/file/k2ydui0i7l4kyq6/NordTheme_2_4_4_0.crx/file"
        "https://www.mediafire.com/file/60msblhs8n4kdwz/Ublock_Orgin_extension_1_41_2_0.crx/file"

    )
    foreach ($URL in $URLs) {

        $DownloadLink2 = (Invoke-WebRequest -Uri $URL -UseBasicParsing).Links | sort-object href -Unique | Select-Object href | Select-String -Pattern 'https://download' -SimpleMatch
        $DownloadLink1 = $DownloadLink2 -replace "@{href=" -replace "" ; $Source = $DownloadLink1 -replace "}" -replace ""
        $DIR = $(get-location).Path ; $APP = ($Source.Split('/',6) | Select -Index 5) ; $DIRAPP = $DIR + "\" + $APP
        Write-Host("Downloading $APP...") -Fore Yellow
        Start-BitsTransfer -Source $Source -Destination $DIRAPP

    }

    # ======== Chrome Settings ======== #
    # Set Extensions root key 
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions" -EA SilentlyContinue 
    # Set Nord Theme extension root key
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\Nord" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\Nord" -Name "Path" -Type String -Value "C:\Users\Default\Links\NordTheme_2_4_4_0.crx" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\Nord" -Name "Version" -Type String -Value "2.4.4" -Force -EA SilentlyContinue 
    # Set Bit Warden extension root key
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\Ward" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\Ward" -Name "Path" -Type String -Value "C:\Users\Default\Links\BitWarden_extension_1_56_4_0.crx" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\Ward" -Name "Version" -Type String -Value "2" -Force -EA SilentlyContinue 
    # Set Ublock Origin extension root key
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\UORG" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\UORG" -Name "Path" -Type String -Value "C:\Users\Default\Links\Ublock_Orgin_extension_1_41_2_0.crx" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Google\Chrome\Extensions\UORG" -Name "Version" -Type String -Value "2" -Force -EA SilentlyContinue 

    # ======== Brave Settings ======== #
    # Set Extensions root key 
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions" -EA SilentlyContinue 
    # Set Nord Theme extension root key
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\Nord" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\Nord" -Name "Path" -Type String -Value "C:\Users\Default\Links\NordTheme_2_4_4_0.crx" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\Nord" -Name "Version" -Type String -Value "2.4.4" -Force -EA SilentlyContinue 
    # Set Bit Warden extension root key
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\Ward" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\Ward" -Name "Path" -Type String -Value "C:\Users\Default\Links\BitWarden_extension_1_56_4_0.crx" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\Ward" -Name "Version" -Type String -Value "2" -Force -EA SilentlyContinue 
    # Set Ublock Origin extension root key
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\UORG" -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\UORG" -Name "Path" -Type String -Value "C:\Users\Default\Links\Ublock_Orgin_extension_1_41_2_0.crx" -Force -EA SilentlyContinue 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\BraveSoftware\Brave-Browser\Extensions\UORG" -Name "Version" -Type String -Value "2" -Force -EA SilentlyContinue 

    $Currentlocation = (Get-Location).path
    sl $env:USERPROFILE\Desktop\
    Get-ChildItem *.lnk | foreach { Remove-Item -Path $_.FullName }
    Get-ChildItem $env:Public\Desktop\*.lnk | ForEach-Object { Remove-Item $_ }
    sl $Currentlocation
    }


#=====[ Software Removal ]=====#
# OneDrive Uninstallation
Write-Host "Uninstalling OneDrive..."
Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
Start-Sleep -s 2
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $onedrive)) {
$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue}

$Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "*3DViewer*"
        "*3dbuilder*"
        "*ACGMediaPlayer*"
        "*ActiproSoftwareLLC*"
        "*AdobePhotoshopExpress*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*AssignedAccessLockApp*"
        "*AutodeskSketchBook*"
        "*BethesdaSoftworks.FalloutShelter*"
        "*Bing*"
        "*BubbleWitch3Saga*"
        "*CandyCrush*"
        "*CommsPhone*"
        "*ConnectivityStore*"
        "*Dolby*"
        "*Duolingo-LearnLanguagesforFree*"
        "*EclipseManager*"
        "*Facebook*"
        "*FarmVille2CountryEscape*"
        "*FeedbackHub*"
        "*Flipboard*"
        "*Getstarted*"
        "*HiddenCity*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*LinkedInforWindows*"
        "*Linkedin*"
        "*Microsoft.3dbuilder*"
        "*Microsoft.549981C3F5F10*"
        "*Microsoft.Asphalt8Airborne*"
        "*Microsoft.BingFinance*"
        "*Microsoft.BingNews*"
        "*Microsoft.BingWeather*"
        "*Microsoft.Caclulator*"
        "*Microsoft.DrawboardPDF*"
        "*Microsoft.GetHelp*"
        "*Microsoft.Getstarted*"
        "*Microsoft.MSPaint*"
        "*Microsoft.Messaging*"
        "*Microsoft.MicrosoftOfficeHub*"
        "*Microsoft.MicrosoftSolitaireCollection*"
        "*Microsoft.MsixPackagingTool*"
        "*Microsoft.OneConnect*"
        "*Microsoft.People*"
        "*Microsoft.Print3D*"
        "*Microsoft.SkypeApp*"
        "*Microsoft.Wallet*"
        "*Microsoft.Windows.Photos*"
        "*Microsoft.WindowsAlarms*"
        "*Microsoft.WindowsCamera*"
        "*Microsoft.WindowsFeedbackHub*"
        "*Microsoft.WindowsMaps*"
        "*Microsoft.WindowsSoundRecorder*"
        "*Microsoft.WindowsStore*"
        "*Microsoft.Xbox.TCUI*"
        "*Microsoft.XboxApp*"
        "*Microsoft.XboxGameOverlay*"
        "*Microsoft.XboxGamingOverlay*"
        "*Microsoft.XboxIdentityProvider*"
        "*Microsoft.XboxSpeechToTextOverlay*"
        "*Microsoft.YourPhone*"
        "*Microsoft.ZuneMusic*"
        "*Microsoft.ZuneVideo*"
        "*Microsoft3DViewer*"
        "*MicrosoftOfficeHub*"
        "*MinecraftUWP*"
        "*MixedReality*"
        "*Netflix*"
        "*Office.Sway*"
        "*OneCalendar*"
        "*OneNote*"
        "*Paint*"
        "*PandoraMediaInc*"
        "*PinningConfirmationDialog*"
        "*Royal Revolt*"
        "*SecureAssessmentBrowser*"
        "*Sketchable*"
        "*SkypeApp*"
        "*Speed Test*"
        "*Sticky*"
        "*Store*"
        "*Sway*"
        "*Todos*"
        "*Twitter*"
        "*Viber*"
        "*WindowsCalculator*"
        "*WindowsCamera*"
        "*WindowsMaps*"
        "*WindowsPhone*"
        "*WindowsScan*"
        "*WindowsSoundRecorder*"
        "*Wunderlist*"
        "*Xbox*"
        "*XboxApp*"
        "*XboxGameOverlay*"
        "*XboxGamingOverlay*"
        "*XboxOneSmartGlass*"
        "*XboxSpeechToTextOverlay*"
        "*Xboxapp*"
        "*YourPhone*"
        "*advertising*"
        "*appconnector"
        "*bing*"
        "*bingfinance*"
        "*bingnews*"
        "*bingsports*"
        "*bingweather*"
        "*candy*"
        "*commsphone*"
        "*connectivitystore*"
        "*dropbox*"
        "*feed*"
        "*flaregamesGmbH.RoyalRevolt2*"
        "*freshpaint*"
        "*getstarted*"
        "*king.com.CandyCrushSodaSaga*"
        "*messag*"
        "*microsoft.windowscommunicationsapps*"
        "*mspaint*"
        "*netflix*"
        "*office*"
        "*officehub*"
        "*onenote*"
        "*people*"
        "*photos*"
        "*print3D*"
        "*reality*"
        "*sketch*"
        "*skype*"
        "*skypeapp*"
        "*solit*"
        "*solitaire*"
        "*solitairecollection*"
        "*soundrecorder*"
        "*sway*"
        "*twitter*"
        "*wallet*"
        "*windowsalarms*"
        "*windowscamera*"
        "*windowscommunicationsapps*"
        "*windowsmaps*"
        "*windowsphone*"
        "*xbox*"
        "*xboxapp*"
        "*yourphone*"
        "*zune*"
        "*zunemusic*"
        "*zunevideo*"
        "DellInc.DellDigitalDelivery"
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingTranslator"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
        "microsoft.windowscommunicationsapps"


    )
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -allusers -Name $Bloat| Remove-AppxPackage -allusers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
            }

# Uninstall specific bloatware
        Get-Package -Name "*office*" | Uninstall-Package
        Get-Package -Name "*Microsoft 365*" | Uninstall-Package

#=====[ Software Installtion ]=====#
# Install Software Management utility Chocolatey.
# Write Script to Install Chocolately
Set-Content -Path 'C:\Automation\Choco00.ps1' -Value {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Set-Location -Path C:\Automation
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    }

# Invoke Script to Install Chocolately
    Invoke-Expression 'cmd /c start powershell -Command { powershell.exe C:\Automation\Choco00.ps1 }'

## Install the older better Media Player
    Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

##  Install the older better calculator
    $URL = 'https://www.mediafire.com/file/8rzj2o2apgn7t8r/oldcalcWin11Win10.zip/file'
    $DownloadLink2 = (Invoke-WebRequest -Uri $URL -UseBasicParsing).Links | sort-object href -Unique | Select-Object href | Select-String -Pattern 'https://download' -SimpleMatch
    $DownloadLink1 = $DownloadLink2 -replace "@{href=" -replace "" ; $Source = $DownloadLink1 -replace "}" -replace ""
    $DIR = $(get-location).Path ; $APP = ($Source.Split('/',6) | Select -Index 5) ; $DIRAPP = $DIR + "\" + $APP
    Start-BitsTransfer -Source $Source -Destination $DIRAPP
    Expand-Archive -LiteralPath 'C:\temp\oldcalcWin11Win10.zip' -DestinationPath C:\temp\
    Start C:\temp\OldClassicCalc-2.0-setup.exe
    Sleep 4
    $wshell = New-Object -ComObject wscript.shell;
    $wshell.AppActivate('Setup Old Classic Calculator for Windows 11 and Windows 10')
    Sleep 4
    $wshell.SendKeys('~')
    Sleep 2
    $wshell.SendKeys("%(N)")
    Sleep 2
    $wshell.SendKeys("%(D)")
    Sleep 2
    $wshell.SendKeys("%(N)")
    Sleep 4
    $wshell.SendKeys("%(I)")
    Sleep 3
    $wshell.SendKeys(' ')
    Sleep 1
    $wshell.SendKeys('{TAB}')
    Sleep 2
    $wshell.SendKeys(' ')
    Sleep 2
    $wshell.SendKeys("%(F)")
    sleep 10
    Remove-Item -Recurse -Force C:\temp\OldClassicCalc-2.0-setup.exe -EA SilentlyContinue
    Remove-Item -Recurse -Force C:\temp\oldcalcWin11Win10.zip -EA SilentlyContinue

### Running Shutup10 and using recomended settings
    Import-Module BitsTransfer      
    choco install shutup10 -y
    Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination ".\ooshutup10.cfg"
    OOSU10 ooshutup10.cfg /quiet
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination ".\OOSU10.exe"
    ./OOSU10.exe ooshutup10.cfg /quiet

#=====[ Step 1
#   Source Variable
    $Source = "https://od.lk/d/NzdfMzQ1OTczNTdf/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

#   Directory Variable
    $DIR = "C:\temp"
#   Split the source by slash, and then get everything after the last slash then store as variable
    $APP = ($Source.Split('/',6) | Select -Index 5)
#   Combine Directory Variable and File Variable Name into a new variable
    $DIRAPP = $DIR + "\" + $APP

#   Test to see if the app bundle already exists -- and if it does remove it
    if((Test-Path -Path $DIRAPP -PathType Leaf) -eq  $true){ Remove-Item $DIRAPP -Recurse -Force -Confirm:$false }

#   Using BitsTransfer, download the application from the source to its new location, using these dynamic variables
    Write-Host("Downloading $APP...") -Fore Yellow
    Start-BitsTransfer -Source $Source -Destination $DIRAPP

#   See if winget is installed by trying the command, if it is not installed then this will error thus attempting to install winget
    try { winget -v }
    catch { Add-AppPackage -path $DIRAPP }

########################################################################################################################
#=====[ Scheduled Tasks ]=====#
########################################################################################################################

#=====[ Creating Scheduled Task ]=====#
# Create script for Active Setup
Write-Host('Creating script for active setup...') -Fore White
Set-Content -Path 'C:\Automation\atom.ps1' -Value {

Invoke-Expression 'cmd /c start powershell -Command { powershell.exe "C:\Automation\Win-Update.ps1" }'
Invoke-Expression 'cmd /c start powershell -Command { powershell.exe "C:\Automation\Choco.ps1" }'
Invoke-Expression 'cmd /c start powershell -Command { powershell.exe "C:\Automation\WSL_Ubunutu_01.ps1"}' 
}

# Set the registry key for Active-Setup
Write-Host('Settings registry key for active setup...') -Fore White
reg add "HKLM\Software\Microsoft\Active Setup\Installed Components\ATOM" /v "StubPath" /d "Powershell.exe C:\Automation\atom.ps1" /t REG_SZ /f


### Create task to reboot after updates have been installed.
Write-Host('Creating Scheduled Task to reboot after applying updates...') -Fore White
$ScriptLocation = 'C:\Automation\Reboot.ps1'
$day = 'Monday'
$time = '1am'
$Task = 'Reboot to apply Windows Updates'
$TaskAction = New-ScheduledTaskAction -Execute $ScriptLocation
$TaskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $time
Register-ScheduledTask -Action $TaskAction -Trigger $Tasktrigger -TaskName $Task -User "System" -RunLevel Highest

### Create task to Set a Restore point, clean the disk, and download and apply updates.
Write-Host('Creating Scheduled Task to Apply updates...') -Fore White
$ScriptLocation = 'C:\Automation\AutomaticAdministration.ps1'
$day = 'Sunday'
$time = '9pm'
$Task = 'Apply Windows Updates'
$TaskAction = New-ScheduledTaskAction -Execute $ScriptLocation
$TaskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $time
Register-ScheduledTask -Action $TaskAction -Trigger $Tasktrigger -TaskName $Task -User "System" -RunLevel Highest

Set-Content -Path 'C:\Automation\WSL_Ubunutu_00.ps1' -Value {
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
    
    Set-Content -Path 'C:\Automation\WSL_Ubunutu_01.ps1' -Value {
    # Download and install the framework needed for windows Subsystem
    Start-BitsTransfer -Source "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi" -Destination "C:\Automation\wsl_update_x64.msi"
    Start-Process msiexec.exe -Wait -ArgumentList '/I C:\Automation\wsl_update_x64.msi /quiet'

    # Wait until the application is installed before proceeding
    do {
        Start-Sleep -Seconds 1 
        $LNXCHeck = (get-wmiobject Win32_Product | Sort-Object -Property Name |  Where-Object Name -match "Windows SubSystem for Linux Update").Name
        $LNXName  = "Windows SubSystem for Linux Update"
        $TestLNX = $LNXName -eq $LNXCHeck
    } until ($TestLNX -eq $true)

    # Set the subsystem preference to version 2
    invoke-expression 'cmd /c start powershell -Command { wsl --set-default-version 2 }' ; Start-Sleep -s 7

    # Download Ubuntu
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri https://aka.ms/wslubuntu -OutFile C:\Automation\Ubuntu.appx -UseBasicParsing

    # If Ubuntu did not download; then attempt to another method
    $UbuApx = "C:\Automation\Ubuntu.appx"
    if (Test-Path -Path $UbuApx) {
    # IF File exists continue
    
        } else {
    # IF File does not exist download and then continue
    Start-BitsTransfer -Source "https://wslstorestorage.blob.core.windows.net/wslblob/CanonicalGroupLimited.UbuntuonWindows_2004.2021.825.0.AppxBundle" -Destination "C:\Automation\Ubuntu.appx"
    }

    # Install this the Ubuntu Package
    Add-AppxPackage C:\Automation\Ubuntu.appx ; Start-Sleep -s 7 
    
    # Launch bash first time to install updates
    invoke-expression 'cmd /c start powershell -Command { Start bash }'

    }

    $URL="https://javadl.oracle.com/webapps/download/AutoDL?BundleId=246474_2dee051a5d0647d5be72a7c0abff270e"
    Invoke-WebRequest -UseBasicParsing -OutFile jre8.exe $URL

    Start-Process .\jre8.exe '/s REBOOT=0 SPONSORS=0 AUTO_UPDATE=0' -wait

    $JREVersion = Get-ChildItem -Path "C:\Program Files\Java" -name | Where-Object { -not $_.PsIsContainer } | Sort-Object LastWriteTime -Descending | Select-Object -first 1 

    Write-Host "JREVersion: $JREVersion"
    $JREPath = "C:\Progra~1\Java\$JREVersion"
    Write-Host  "JREPath" + $JREPath
    Write-Host "Downloading 64 bit of JRE"

    Write-Host "JRE package URL " $URL


}


#=====[ Disabling Scheduled Tasks ]=====#

$DisableTasks = @(

    #Disable Tasks
    "Windows Defender Cache Maintenance"
    "Windows Defender Cleanup"
    "Windows Defender Scheduled Scan"
    "Windows Defender Verification"
    "QueueReporting"
    "Microsoft Compatibility Appraiser"
    "ProgramDataUpdater"
    "StartupAppTask"
    "Proxy"
    "CreateObjectTask"
    "Consolidator"
    "UsbCeip"
    "Microsoft-Windows-DiskDiagnosticDataCollector"
    "DmClient"
    "DmClientOnScenarioDownload"
    "FamilySafetyMonitor"
    "FamilySafetyRefreshTask"
    "ScheduledDefrag"
    "SaveTask"
    "SaveTaskLogon"
    "DmClientOnScenarioDownload "
    "OfficeTelemetryAgentFallBack2016 "
    "OfficeTelemetryAgentLogOn2016"
    "XblGameSaveTask"
    "XblGameSaveTaskLogon"

    )
    foreach ($disTask in $DisableTasks) {
        Get-ScheduledTask -TaskName $disTask | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
        }

########################################################################################################################
#=====[ Automatic Administration ]=====#
########################################################################################################################

# Create blank start menu layout
Set-Content -Path 'C:\Users\Public\Documents\Start_Layout.xml' -Value {
    <LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
      <LayoutOptions StartTileGroupCellWidth="6" />
      <DefaultLayoutOverride>
        <StartLayoutCollection>
          <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
      </DefaultLayoutOverride>
    </LayoutModificationTemplate>}
# Import blank Start menu layout    
    Import-StartLayout -LayoutPath 'C:\Users\Public\Documents\Start_Layout.xml' -MountPath C:\

# Setup Disk Cleanup for the C: Drive
Write-Host('Please choose the items that need to be removed inside of Cleanmgr...') -Fore White
$SageValue = [int](Get-ItemProperty -Path "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" -Name "StateFlags0110").StateFlags0110
if ($SageValue -ne "2"){
	cleanmgr /D C /sageset:0110110
	$clnmgr = (Get-Process cleanmgr).id ; Wait-Process -Id $clnmgr 
	cleanmgr /D C /sagerun:0110110
}

if ($SageValue -eq "2"){ cleanmgr /D C /sagerun:0110110 }

# Define Task Manager Details, by setting perferences.
$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
Do {
Start-Sleep -Milliseconds 100
$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
} Until ($preferences)
Stop-Process $taskmgr
$preferences.Preferences[28] = 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences

##  Set up prerequisites to install  PSWindowsUpdate.
### We install the package NuGet as a prerequisite to intsall PSWindowsUpdate.
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

### We add PSGallery to the trusted installer to our reposistories list.
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

### We install the module PSWindowsUpdate.
        Install-Module PSWindowsUpdate

### We add Microsoft Windows as a valid Windows Update supplier, and auto confirm.
        Add-WUServiceManager -ServiceID "7971f918-a847-4430-9279-4a52d1efe18d" -Confirm:$false

########################################################################################################################
#=====[ Scripts ]=====#
########################################################################################################################

### Create Win-update.ps1 script
Set-Content -Path 'C:\Automation\Win-Update.ps1' -Value {
    #Define Title
        $host.UI.RawUI.WindowTitle = "Update Windows"
    #Define Function to set color
        function color ($bc,$fc) {
            $a = (Get-Host).UI.RawUI
            $a.BackgroundColor = $bc
            $a.ForegroundColor = $fc ; cls}

    #Set color
        color "DarkGray" "White"

    #Set size of console shell
        cmd /c MODE con:cols=135 lines=30

    # Ensure that services are started
        Start-Service -Name BITS
        Start-Service -Name wuauserv
        Start-Service -Name cryptSvc
        Start-Service -Name msiserver

    #Run the script to install Windows Updates.
        Write-Host('Searching, Downloading, and Installing Updates...')
        Install-WindowsUpdate -AcceptAll -MicrosoftUpdate
   }


##  Create script to Set a restore point, run diskcleanup, and run windows updates.
Set-Content -Path 'C:\Automation\AutomaticAdministration.ps1' -Value {
        #Define Title
        $host.UI.RawUI.WindowTitle = "Automatic Administration"
### Create Restore Point before letting the script make changes.
    Write-Host('Creating Restore Point...') -Fore White
    Enable-ComputerRestore -Drive "C:\"
    $time = (Get-Date).ToString("yyyy:MM:dd")
    Checkpoint-Computer -Description $time -RestorePointType "MODIFY_SETTINGS"
        Start-Sleep -s 180

### Install Windows Updates
    Invoke-Expression 'cmd /c start powershell -Command { powershell.exe "C:\Automation\Win-Update.ps1"}' 

### Run the Disk Cleanup tool
    $clnmgr = (Get-Process cleanmgr).id ; Wait-Process -Id $clnmgr 
    cleanmgr /D C /sagerun:0110110

# Cleanup the WinSXS component folder using DISM
    dism /Online /Cleanup-Image /AnalyzeComponentStore  /NoRestart
    dism /online /Cleanup-Image /StartComponentCleanup  /NoRestart



}   

## Create Script to apply updates and reboot.
Write-Host('Create script to reboot after applying updates...') -Fore White
Set-Content -Path 'C:\Automation\Reboot.ps1' -Value {cmd /c shutdown -r -c " " -t 180}

########################################################################################################################
#=====[ Etcetera ]=====#
########################################################################################################################

##  Power Management Settings
# Set Power Profile to High Performance
            powercfg.exe /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
# Disable Hibernation
            powercfg /h off
# Turn off the display when on battery, setting this time to anything other than 0 will be the trigger time in minutes
            powercfg -change -monitor-timeout-ac 0
# Turn off the display when Plugged In, setting this time to anything other than 0 will be the trigger time in minutes
            powercfg -change -monitor-timeout-dc 0
# Put the computer to sleep when on battery, setting this time to anything other than 0 will be the trigger time in minutes
            powercfg -change -standby-timeout-ac 0
# Put the computer to sleep when Plugged , setting this time to anything other than 0 will be the trigger time in minutes
            powercfg -change -standby-timeout-dc 0
# Choose what to do when I close the lid - On battery - Do Nothing
            powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
# Choose what to do when I close the lid - Plugged In - Do Nothing
            powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
            powercfg -SetActive SCHEME_CURRENT

#=====[ Cleanup Stage
#   Delete the copied file after the script has run
    if((Test-Path -Path $DIRAPP -PathType Leaf) -eq  $true){ Remove-Item $DIRAPP -Recurse -Force -Confirm:$false }

 ### Enable Features
            dism /online /disable-feature /featurename:SearchEngine-Client-Package /NoRestart

### Set the Ground work for us to install the Windows Subsystem for Linux
             Invoke-Expression 'cmd /c start powershell -Command { powershell.exe "C:\Automation\WSL_Ubunutu_00.ps1"}' 
 
 ### Download and Install PowerShell 7+
             Set-Location -Path C:\temp
             wget -Uri "https://github.com/PowerShell/PowerShell/releases/download/v7.1.3/PowerShell-7.1.3-win-x64.msi"  -Outfile C:\temp\PowerShell-7.1.3-win-x64.msi
             Unblock-File -Path C:\temp\PowerShell-7.1.3-win-x64.msi
             Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\PowerShell-7.1.3-win-x64.msi /quiet'

# Enable .DOTNET Framework 3.5.1
            Dism /online /Enable-Feature /FeatureName:"NetFx3" /NoRestart
# Enable .DOTNET Framework 4.+.+
            DISM /Online /Enable-Feature /FeatureName:"NetFx4" /NoRestart            

# Download 1812 
    Write-Host "Downloading 1812.." -Fore Yellow  
    $Source_MP3 = 'http://download.publicradio.org/podcast/minnesota/classical/programs/free-downloads/2019/10/01/daily_download_bonus_20191001_128.mp3'
    $DIRAPP_MP3 = "C:\Users\Public\Music\1812.mp3"
    Start-BitsTransfer -Source $Source_MP3 -Destination $DIRAPP_MP3   
# Play 1812  
    Add-Type -AssemblyName presentationCore
    $mediaPlayer = New-Object system.windows.media.mediaplayer
    $mediaPlayer.open("C:\Users\Public\Music\1812.mp3")
    $mediaPlayer.Play()

## Remove Temporary Files
    $Path = "C:WindowsTemp"
    $Days = "-14"
    $CurrentDate = Get-Date
    $OldDate = $CurrentDate.AddDays($Days)
    Get-ChildItem $Path -Recurse | Where-Object { $_.LastWriteTime -lt $OldDate } | Remove-Item -force    

## Repair possible damaged system files
    sfc /scannow
    DISM /Online /Cleanup-Image /CheckHealth /NoRestart /Quiet
    DISM /Online /Cleanup-Image /ScanHealth /NoRestart /Quiet
    DISM /Online /Cleanup-Image /RestoreHealth /NoRestart /Quiet

# Set the Password for the Administration User Account.
Write-Host('Setting User...') -Fore Gray
$env:SVCUSER="ion"
$env:SVCPASS='Gladiator2-Maven'
$SecurePass=ConvertTo-SecureString $env:SVCPASS -AsPlainText -Force
New-LocalUser -Name "$env:SVCUSER" -Password $SecurePass -AccountNeverExpires -UserMayNotChangePassword
Set-LocalUser -Name "$env:SVCUSER" -PasswordNeverExpires $false
cmd /c net localgroup Administrators /add ion

# Reboot Confirmation Prompt, Yes, No, Cancel
Add-Type -AssemblyName PresentationCore,PresentationFramework
$msgBody = "Reboot the computer now?"
$msgTitle = "Confirm Reboot"
$msgButton = 'YesNoCancel'
$msgImage = 'Warning'
$Result = [System.Windows.MessageBox]::Show($msgBody,$msgTitle,$msgButton,$msgImage)
Write-Host "The user chose: $Result [" ($result).value__ "]"


    If ($Result -eq '6') {
            shutdown -r -c " " -t 15
                         }

    If ($Result -eq '7') {
            shutdown -a
                         }

    If ($Result -eq '2') {
            Write-Host 'Cancel Action Chosen'
                         }

