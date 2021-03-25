# Hide most errors and continue
$ErrorActionPreference = 'SilentlyContinue'

# If not run as admin, ask if user wants to run as admin or quit.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "This script needs to be run as Admin. If you want to run this as admin, press 'y', otherwise press 'n' to quit! "
    if ($( Read-Host -Prompt "Do you want to re-run this script as admin? (y/n)") -eq 'y') {
        exit;
    }
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# This function stores a list of apps to remove in "apps" then goes through the list and tries to remove each
function RemoveApps {
    Write-Output "> Attempting to remove apps"

    $apps = @(
        # If you want to keep any of the apps listed, 
        # simply add "#" (without the quotes) before the app 
        # like so:
        # "*Microsoft.BingTranslator*"

        "*Microsoft.3DBuilder*"
        "*Microsoft.549981C3F5F10*"   # Cortana related
        "*Microsoft.Asphalt8Airborne*"
        "*Microsoft.BingFinance*"
        "*Microsoft.BingNews*"
        "*Microsoft.BingSports*"
        "*Microsoft.BingTranslator*"
        "*Microsoft.BingWeather*"
        "*Microsoft.GetHelp*"
        "*Microsoft.Getstarted*"
        "*Microsoft.Messaging*"
        "*Microsoft.Microsoft3DViewer*"
        "*Microsoft.MicrosoftOfficeHub*"
        "*Microsoft.MicrosoftSolitaireCollection*"
        "*Microsoft.MicrosoftStickyNotes*"
        "*Microsoft.MixedReality.Portal*"
        "*Microsoft.Office.OneNote*"
        "*Microsoft.OneConnect*"
        "*Microsoft.People*"
        "*Microsoft.Print3D*"
        "*Microsoft.SkypeApp*"
        "*Microsoft.WindowsFeedbackHub*"
        "*Microsoft.WindowsMaps*"
        "*Microsoft.WindowsSoundRecorder*"
        "*Microsoft.Xbox.TCUI*"
        "*Microsoft.XboxApp*"
        "*Microsoft.XboxGameOverlay*"
        "*Microsoft.XboxGamingOverlay*"
        "*Microsoft.XboxIdentityProvider*"
        "*Microsoft.XboxSpeechToTextOverlay*" # NOTE: This app may not be able to be reinstalled!
        "*Microsoft.ZuneMusic*"
        "*Microsoft.ZuneVideo*"
        "*king.com.BubbleWitch3Saga*"
        "*king.com.CandyCrushSaga*"
        "*king.com.CandyCrushSodaSaga*"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"
    )

    # Iterate through apps list, try and remove the package, in some cases removal may fail
    foreach ($app in $apps) {
        Write-Output "Attempting to remove $app"
        Get-AppxPackage -Name $app | Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
    }
} # End function RemoveApps


# Function that takes in a message to display on screen and registry path to apply changes to the registry
function RegImport {
    param 
    (
        $Message,
        $Path
    )

    Write-Output $Message
    reg import $path
}


Clear-Host
Write-Output " Choose if you want to run all functions in the script or choose what to for each step."
Write-Output " Option (1) includes all apps I use installed via Chocolatey which might take a long time."
Write-Output " If you are re-running this script after an update or big change to the system you should use option (2)"
Write-Output "-------------------------------------------------------------------------------------------"
Write-Output "(1) Run everything"
Write-Output "(2) Re-run with exceptions (Skips installing apps for example)"
Write-Output "(3) Configure manually (recommended)"
Write-Output ""

# Wait for user choice
Do { $Mode = Read-Host "Please select a valid option (1/2)" }
while ($Mode -ne '1' -and $Mode -ne '2' -and $Mode -ne '3')

# Create a restore point 
Write-Host "Creating System Restore Point"
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "Win10Setup" -RestorePointType "MODIFY_SETTINGS"

if ($Mode -eq '1') {

}
elseif ($Mode -eq '2') {
    
}
elseif ($Mode -eq '3') {
    if ($( Read-Host -Prompt "Remove pre-installed apps (y/n)" ) -eq 'y') {
        $PSBoundParameters.Add('RemoveApps', $RemoveApps)   
    }

    Write-Output " If you do not install Chocolatey package manager, a lot of the options will be unavailable."
    if ($( Read-Host -Prompt "Install Chocolatey package manager? (y/n)") -eq 'y') {
        $PSBoundParameters.Add('InstallChoco', $InstallChoco)

        if ($( Read-Host -Prompt "Install chosen apps via Chocolatey (y/n)" ) -eq 'y') {
            $PSBoundParameters.Add('InstallAllApps', $InstallAllApps)
        }

        if ($( Read-Host -Prompt "Do you want to install O&O ShutUp10 and apply provided config? (y/n)") -eq 'y') {
            $PSBoundParameters.Add('ApplyShutup10', $ApplyShutup10)
        }
    }

    # If not using Shutup10, provide some commonly modified options instead
    if ($PSBoundParameters.Keys -ne 'ApplyShutup10') {
        if ($( Read-Host -Prompt "Hide the onedrive folder in windows explorer? (y/n)" ) -eq 'y') {
            $PSBoundParameters.Add('UninstallOnedrive', $DisableOnedrive)   
        }
    
        if ($( Read-Host -Prompt "Hide the 3D objects folder in windows explorer? (y/n)" ) -eq 'y') {
            $PSBoundParameters.Add('Disable3dObjects', $Disable3dObjects)   
        }

        if ($(Read-Host -Prompt "Disable Cortana (y/n)") -eq 'y') {
            $PSBoundParameters.Add('DisableCortana', $DisableCortana)
        }
    }

    if ($( Read-Host -Prompt "Enable Windows 10 dark mode (y/n)") -eq 'y') {
        $PSBoundParameters.Add('EnableDarkMode', $EnableDarkMode)
    }

    if ($( Read-Host -Prompt "Enable/enforce some security tweaks (y/n)") -eq 'y') {
        $PSBoundParameters.Add('TweakSecurity', $TweakSecurity)
    }

    if ($( Read-Host -Prompt "Disable background application access (y/n)")) {
        $PSBoundParameters.Add('DisableBackgroundApps', $DisableBackgroundApps)
    }

    Write-Host "Misc. tweaks are listed on my website (https://kellegram.xyz) as well as on my repository"
    if ($( Read-Host -Prompt "Perform other misc. tweaks (y/n)") -eq 'y') {
        $PSBoundParameters.Add('TweakMisc', $TweakMisc)
    }

}
else { 
    # This should never happen
    Write-Output " You shouldn't be seeing this message :o"
    Write-Output " Try running the script again in a new window and make sure to follow instructions correctly."
    Write-Output " If it fails again, leave an issue in the repository and make sure to provide the error: "
    Write-Output " Error: Failed during multiple choice 01."
    Write-Output " Press any key to continue..."
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

switch ($PSBoundParameters.Keys) {
    'RemoveApps' {
        RemoveApps
    }
    'InstallChoco' {
        Write-Host "Installing Chocolatey"
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        choco install chocolatey-core.extension -y
        Write-Host "Done installing Chocolatey"
    }
    'InstallAllApps' {
        Write-Host "Beginning installation of apps via Chocolatey"
        choco install firefox 7zip.install notepadplusplus.install vlc vcredist140 git.install openssh autohotkey.portable teamviewer gimp vscode inkscape treesizefree winscp.install chocolateygui wireshark sumatrapdf.install irfanview microsoft-windows-terminal audacity everything qbittorrent steam tor-browser rufus cpu-z.install telegram.install etcher blender foobar2000 kitty discord handbrake sharex freefilesync obs-studio hwinfo teracopy powertoys -y
        Write-Host "Done installing apps"
    }
    'ApplyShutup10' {
        Write-Host "Running O&O Shutup with Recommended Settings"
        Import-Module BitsTransfer
        Start-BitsTransfer -Source "https://raw.githubusercontent.com/Kellegram/Win10-setup/master/ooshutup10.cfg" -Destination ooshutup10.cfg
        choco install shutup10 -y
        OOSU10 ooshutup10.cfg /quiet
        Write-Host "Done running Shutup10"
    }
    'UninstallOnedrive' {
        Write-Host "Disabling OneDrive..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
        Write-Host "Uninstalling OneDrive..."
        Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
        Start-Sleep -s 2
        $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        If (!(Test-Path $onedrive)) {
            $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        }
        Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
        Start-Sleep -s 2
        Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
        Start-Sleep -s 2
        Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
        If (!(Test-Path "HKCR:")) {
            New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
        }
        Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
        $wshell.Popup("Operation Completed", 0, "Done", 0x0)
    }
    'Disable3dObjects' {
        RegImport "> Hiding the 3D objects folder in windows explorer..." $PSScriptRoot\Regfiles\Hide_3D_Objects_Folder.reg
    }
    'DisableMusic' {
        RegImport "> Hiding the music folder in windows explorer..." $PSScriptRoot\Regfiles\Hide_Music_folder.reg
    }
    'DisableBingSearches' {
        RegImport "> Disabling bing in windows search..." $PSScriptRoot\Regfiles\Disable_Bing_Searches.reg
    }
    'DisableLockscreenTips' {
        RegImport "> Disabling tips & tricks on the lockscreen..." $PSScriptRoot\Regfiles\Disable_Lockscreen_Tips.reg
    }
    'DisableWindowsSuggestions' {
        RegImport "> Disabling tips, tricks and suggestions in the startmenu and settings..." $PSScriptRoot\Regfiles\Disable_Windows_Suggestions.reg
    }
    'DisableIncludeInLibrary' {
        RegImport "> Disabling 'Include in library' in the context menu..." $PSScriptRoot\Regfiles\Disable_Include_in_library_from_context_menu.reg
    }
    'DisableGiveAccessTo' {
        RegImport "> Disabling 'Give access to' in the context menu..." $PSScriptRoot\Regfiles\Disable_Give_access_to_context_menu.reg
    }
    'DisableShare' {
        RegImport "> Disabling 'Share' in the context menu..." $PSScriptRoot\Regfiles\Disable_Share_from_context_menu.reg
    }
    'EnableDarkMode' {
        Write-Host "Enabling Dark Mode"
        Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0
        Write-Host "Done enabling Dark Mode"
    }
    'TweakSecurity' {
        Write-Host "Beginning security tweaks"

        Write-Host "Disabling SMB 1.0 protocol..."
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

        # Not much here right now, will expand later

    }
    'DisableCortana' {
        Write-Host "Disabling Cortana..."
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
        If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
            New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
        Write-Host "Done disabling Cortana"
    }
    'DisableBackgroundApps' {
        Write-Host "Disabling Background application access..."
        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*" | ForEach {
            Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
            Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
        }
        Write-Host "Done disabling background apps"
    }
    'TweakMisc' {
        Write-Host "Beginning misc. tweaks..."
        Write-Host "Disabling Bing Search in Start Menu..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
        
        Write-Host "Stopping and disabling Windows Search indexing service..."
        Stop-Service "WSearch" -WarningAction SilentlyContinue
        Set-Service "WSearch" -StartupType Disabled
        Write-Host "Hiding Taskbar Search icon / box..."
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

        Write-Host "Remove Paint3D related stuff"
        $Paint3Dstuff = @(
            "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
            "HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
        )
        #Rename reg key to remove it, so it's revertible
        foreach ($Paint3D in $Paint3Dstuff) {
            If (Test-Path $Paint3D) {
                $rmPaint3D = $Paint3D + "_"
                Set-Item $Paint3D $rmPaint3D
            }
        }

        
    }

}



Write-Output "All tasks in the script have run. Some changes require a PC restart."
Write-Output "It is highly recommended to restart now, before making any other changes to the sytem!"
Write-Output "Press any key to close..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")