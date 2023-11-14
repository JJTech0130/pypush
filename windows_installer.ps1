Import-Module Microsoft.PowerShell.Management

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
  
  Write-Output "Checking if git is installed"
  # Check if Git is installed.
  if (-not (Test-Path "$env:USERPROFILE\AppData\Local\Programs\Git\cmd\git.exe")) {
    # Git is not installed, so download and install it.
    Write-Output "Installing git"
    $gitUrl = "https://github.com/git-for-windows/git/releases/download/v2.42.0.windows.2/Git-2.42.0.2-32-bit.exe"
    $gitInstaller = "$($env:TEMP)\git.exe"
    Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller
    Start-Process -FilePath $gitInstaller -ArgumentList "/SILENT" -Wait
  }
  
  # Create the folder for virtual environments if it doesn't exist.
  if (Test-Path "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs") {
    New-Item "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs" -ItemType Directory
  }
  
  # Create a Python 3.10 virtual environment named "pypush" in the user's home folder.
  python3 -m venv "$env:USERPROFILE\pypush"
  
  # Activate the virtual environment.
  . "$env:USERPROFILE\pypush\Scripts\activate.ps1"
  
  # Install dependencies from the requirements.txt file using pip.
  pip install -r "$env:USERPROFILE\pypush\requirements.txt"
  
  # Clone the "sms-registration" branch of the repository located at https://github.com/beeper/pypush using git.
  git clone -b sms-registration https://github.com/beeper/pypush "$env:USERPROFILE\pypush"
  
  # Change directories to the repository.
  cd "$env:USERPROFILE\pypush"
  
  # Prompt the user for the IP address of their phone.
  $phoneIp = Read-Host "Enter the IP address of your phone: "
  
  # Store the IP address in a variable.
  $phoneIpVariable = Set-Variable -Name phoneIp -Value $phoneIp -Scope Global
  
  # Execute the `python demo.py` script with the phone IP address passed as a parameter.
  python demo.py --phone $phoneIpVariable
  
  # Execute the daemon for reregistration
  python demo.py --daemon
  
