# Hide most errors and continue
$ErrorActionPreference = 'SilentlyContinue'

# If not run as admin, ask if user wants to run as admin or quit.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "This script needs to be run as Admin. If you want to run this as admin, press 'y', otherwise press 'n' to quit! "
    if($( Read-Host -Prompt "Do you want to re-run this script as admin? (y/n)") -eq 'y')
    {
        exit;
    }
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# This function stores a list of apps to remove in "apps" then goes through the list and tries to remove each
function RemoveApps
{
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
    foreach ($app in $apps) 
    {
        Write-Output "Attempting to remove $app"
        Get-AppxPackage -Name $app| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online
    }
} # End function RemoveApps


# Function that takes in a message to display on screen and registry path to apply changes to the registry
function RegImport
{
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

if ($Mode -eq '1')
{

}
elseif ($Mode -eq '2') 
{
    
}
elseif ($Mode -eq '3')
{
    if($( Read-Host -Prompt "Remove pre-installed apps (y/n)" ) -eq 'y')
    {
        $PSBoundParameters.Add('RemoveApps', $RemoveApps)   
    }

    Write-Output " If you do not install Chocolatey package manager, a lot of the options will be unavailable."
    if($( Read-Host -Prompt "Install Chocolatey package manager? (y/n)") -eq 'y')
    {
        $PSBoundParameters.Add('InstallChoco', $InstallChoco)

        if($( Read-Host -Prompt "Install chosen apps via Chocolatey (y/n)" ) -eq 'y')
        {
            $PSBoundParameters.Add('InstallAllApps', $InstallAllApps)
        }

        if($( Read-Host -Prompt "Do you want to install O&O ShutUp10 and apply provided config? (y/n)") -eq 'y')
        {
            $PSBoundParameters.Add('ApplyShutup10', $ApplyShutup10)
        }
    }

    # If not using Shutup10, provide some commonly modified options instead
    if ($PSBoundParameters.Keys -ne 'ApplyShutup10')
    {
        if($( Read-Host -Prompt "Hide the onedrive folder in windows explorer? (y/n)" ) -eq 'y')
        {
            $PSBoundParameters.Add('DisableOnedrive', $DisableOnedrive)   
        }
    
        if($( Read-Host -Prompt "Hide the 3D objects folder in windows explorer? (y/n)" ) -eq 'y')
        {
            $PSBoundParameters.Add('Disable3dObjects', $Disable3dObjects)   
        }

    }

}
else 
{ 
    # This should never happen
    Write-Output " You shouldn't be seeing this message :o"
    Write-Output " Try running the script again in a new window and make sure to follow instructions correctly."
    Write-Output " If it fails again, leave an issue in the repository and make sure to provide the error: "
    Write-Output " Error: Failed during multiple choice 01."
    Write-Output " Press any key to continue..."
    $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

switch ($PSBoundParameters.Keys)
{
    'RemoveApps' 
    {
        RemoveApps
    }
    'DisableOnedrive'
    {
        RegImport "> Hiding the onedrive folder in windows explorer..." $PSScriptRoot\Regfiles\Hide_Onedrive_Folder.reg
    }
    'Disable3dObjects'
    {
        RegImport "> Hiding the 3D objects folder in windows explorer..." $PSScriptRoot\Regfiles\Hide_3D_Objects_Folder.reg
    }
    'DisableMusic'
    {
        RegImport "> Hiding the music folder in windows explorer..." $PSScriptRoot\Regfiles\Hide_Music_folder.reg
    }
    'DisableBingSearches'
    {
        RegImport "> Disabling bing in windows search..." $PSScriptRoot\Regfiles\Disable_Bing_Searches.reg
    }
    'DisableLockscreenTips'
    {
        RegImport "> Disabling tips & tricks on the lockscreen..." $PSScriptRoot\Regfiles\Disable_Lockscreen_Tips.reg
    }
    'DisableWindowsSuggestions'
    {
        RegImport "> Disabling tips, tricks and suggestions in the startmenu and settings..." $PSScriptRoot\Regfiles\Disable_Windows_Suggestions.reg
    }
    'DisableIncludeInLibrary'
    {
        RegImport "> Disabling 'Include in library' in the context menu..." $PSScriptRoot\Regfiles\Disable_Include_in_library_from_context_menu.reg
    }
    'DisableGiveAccessTo'
    {
        RegImport "> Disabling 'Give access to' in the context menu..." $PSScriptRoot\Regfiles\Disable_Give_access_to_context_menu.reg
    }
    'DisableShare'
    {
        RegImport "> Disabling 'Share' in the context menu..." $PSScriptRoot\Regfiles\Disable_Share_from_context_menu.reg
    }
}



Write-Output "All tasks in the script have run. Some changes require a PC restart."
Write-Output "It is highly recommended to restart now, before making any other changes to the sytem!"
Write-Output "Press any key to close..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")