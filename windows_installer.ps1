Import-Module Microsoft.PowerShell.Management

# Prompt the user for the IP address of their phone.
$phoneIp = Read-Host "Enter the IP address of your phone: "

# Check if Python is installed.
Write-Output "Checking if Python is installed"
if (-not (Test-Path "$env:USERPROFILE\AppData\Local\Programs\Python\Python310\python.exe")) {
    # Python is not installed, so download and install it.
    Write-Output "Installing Python"
    $pythonUrl = "https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe"
    $pythonInstaller = "$($env:TEMP)\python.exe"
    Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller
    Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet" -Wait
  }
  
Write-Output "Adding Python to Path"
[Environment]::SetEnvironmentVariable("Path", "$env:Path;$env:USERPROFILE\AppData\Local\Programs\Python\Python310")

  Write-Output "Checking if git is installed"
  # Check if Git is installed.
  if (-not (Test-Path "C:\Program Files\Git\bin\git.exe")) {
    # Git is not installed, so download and install it.
    Write-Output "Installing git"
    $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.42.0.windows.2/Git-2.42.0.2-64-bit.exe"
    $gitInstaller = "$($env:TEMP)\git.exe"
    Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller
    Start-Process -FilePath $gitInstaller -ArgumentList "/SILENT" -Wait
  }

Write-Output "Adding Git to Path"  
[Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\Program Files\Git\bin\")
  
# Create the folder for virtual environments if it doesn't exist.
Write-Output "Creating folder for virtual environment"  
if (Test-Path "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs") {
    New-Item "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs" -ItemType Directory
  }
  
  # Create a Python 3.10 virtual environment named "pypush" in the user's home folder.
Write-Output "Creating virtual environment"  
python -m venv "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs\pypush"
  
# Activate the virtual environment.
Write-Output "Activating virtual environment"  
. "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs\pypush\Scripts\activate.ps1"

cd "$env:USERPROFILE"

# Clone the "sms-registration" branch of the repository located at https://github.com/JJTech0130/pypush using git.
Write-Output "Cloning sms-registration branch"  
git clone -b sms-registration https://github.com/JJTech0130/pypush
  
# Change directories to the repository.
Write-Output "Changing directories"  
cd "$env:USERPROFILE\pypush"
 
# Install dependencies from the requirements.txt file using pip.
Write-Output "Installing dependencies"  
pip install -r "requirements.txt"
    
# Execute the `python demo.py` script with the phone IP address passed as a parameter.
Write-Output "Registering"  
python demo.py --phone $phoneIp 
