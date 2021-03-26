# Win10-setup
Files I use to setup my Windows 10 installations

## Usage

- Manual launch
    1. Click [this](https://github.com/Kellegram/Win10-setup/archive/refs/heads/master.zip) to download latest version of the repo
    2. Unzip the contents to a location of your choice
    3. To run, either:
        - Right click SetupWin10.ps1 and Run with PowerShell then follow instruction to restart with admin permissions
        - Open PowerShell as admin and navigate to the location of the file and run it
    4. Follow the script instructions to perform the setup
    

- Automatic download
    1. Open Powershell as admin (IMPORTANT!!)
    2. Copy and paste the command below into the Powershell window and hit enter

            iex ((New-Object System.Net.WebClient).DownloadString('https://git.io/JYtb6'))
    3. Follow the script instructions as normal
