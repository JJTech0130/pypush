cd "$env:USERPROFILE\pypush"

# Activate the virtual environment
. "$env:USERPROFILE\AppData\Local\Python\VirtualEnvs\pypush\Scripts\activate.ps1"

# Continuously run the demo script in daemon mode
while ($true) {
    python ./demo.py --daemon

    # If the script disconnects, wait 5 minutes before restarting
    Start-Sleep -Seconds 300
}