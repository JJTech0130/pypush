# Overview
This is the Pypush sms-registration branch. This branch allows you to register your phone number to your Apple account as an iMessage alias.

sms-registration is not fully developed yet, and still contains bugs! If you encounter any sort of bug, please join [our Discord](https://discord.gg/BtSbcExKJ9), however please note we cannot get to everyone, so try to figure out any errors yourself before asking.

***Please note:*** You will have to use a client to send messages from your phone. We recommend [Beeper](https://www.beeper.com/), which is the best solution to keep all your chat apps inside one place, including iMessage! You can also use [BlueBubbles](https://bluebubbles.app/) (which requires you to have a server Mac running 24/7) or [Sunbird](https://www.sunbirdapp.com/) (which is closed source and requires you to be a beta tester). One of our community members is also currently working on a BlueBubbles fork that implements a version of Pypush within it, so no server is needed and number reregistration is automatically ran.

However, Beeper is completely free and easy to use, and comes packed with multiple features that rivals native apps. Beeper is currently in the process of removing the waitlist, so you will have to use an invite link shared to you in order to skip the waitlist until this change is made. This app is what most testing is done on, and is by far the most popular in the Android and iMessage community.

# Installation
You will first install Pypush onto your machine. *Please keep in mind that you will have to have a script running on a home server or PC 24/7 to keep your number active! See below for instructions.*

### PNRgateway
In order for Apple to verify your number, a specialized message has to be sent from your phone to Apple's "gateway number" and have the response captured. This number is different for each carrier, however the newest app version should automatically find your gateway number. If PNRgateway cannot find your gateway number, see below for help.

1. Enable USB debugging/ADB on your phone. There are multiple online guides that guide you through this based on your phone.
2. Install the APK. The message link containing the APK is located [here](https://discord.com/channels/1130633272595066880/1145177252015915080/1153070972090470481), and the GitHub repository is [here](https://github.com/JJTech0130/PNRGatewayClientV2).
3. Grant SMS permissions. This will be in the app info page, and on the newer version, there should be a button in the app that does this for you.
4. Connect your phone to the same WiFi network as your host PC, and open the app.

### Pypush
Once you have the PNRgateway app installed on your phone, open it so it is displaying your IP address as you will need it for the next steps. 

Use one of the automated installers for your operating system: [Windows](https://github.com/JJTech0130/pypush/blob/bacefed8b8eb78d5d3f295be5304830665464a04/windows_installer.ps1) or [MacOS/Linux](https://github.com/JJTech0130/pypush/blob/bacefed8b8eb78d5d3f295be5304830665464a04/unix_installer.sh)

For Windows open up PowerShell and navigate to your downloads folder `cd Downloads` and then execute the installer `.\windows_installer.ps1` and follow the prompts. When initial registration has completed execute the file `windows_reregister.ps1` to handle reregistration. This file will reregister your number 5 minutes before registration expires and you must keep the PowerShell window open. Length of registration will gradually increase. 

For MacOS/Linux open up your terminal and navigate to your downloads folder `cd Downloads` or similar. Make the script executable by executing `chmod +x unix_installer.sh`. Execute the script `./unix_installer.sh`. Upon completion a shell script is created called `reregister.sh`. Execute this script in your terminal `./reregister.sh`. This file will reregister your number 5 minutes before registration expires and you must keep the terminal window open. Length of registration will gradually increase.

If you need help or run into errors please reach out on our [Discord](https://discord.gg/BtSbcExKJ9) server.

### Pypush Manual Installation
Make sure you have git and Python installed.

1. `git clone -b sms-registration https://github.com/beeper/pypush`
2. `cd pypush` 

# Number Registration on Linux/MacOS
It is *strongly* recommended to use a Python virtual environment to setup Pypush. This ensures changes in your system's Python installation does not 
break compatibility with Pypush with system updates.

1. If you do not already have a directory where Python virtual environments are located then 
create a directory for your Python virtual environment. If you already have one then skip this step.
Virtual environments are traditionally placed in a hidden folder in your home directory on Linux/MacOS.
It can be created anywhere you wish. These instructions will assume you created it in your home directory.
```
mkdir ~/.venv
```
2. Create a virtual environment using Python 3.10:
```
python -m venv ~/.venv/pypush
```
3. Activate the virtual environment:
```
source ~/.venv/pypush/bin/activate
```
4. Install the required packages using pip:
```
pip install -r requirements.txt
```
5. Run the demo script, replacing `[ip]` with your phone's local IP address:
```
python demo.py --phone [ip]
```
# Number reregistration option 1, automatic reregistration
Automatic reregistration is handled by determining when your imessage registration certificate expires
and reregistering 5 minutes before expiration. Put the following in a text file and save as `pypush_reregister.sh` in your home directory:
```
#!/bin/bash
cd ~/pypush
source ~/.venv/pypush/bin/activate
while true
do
	python ./demo.py --daemon
# If it disconnects, wait 5 minutes before reconnecting to avoid spamming servers
  	sleep 300
done
```
1. Make the reregistration script executable:
```
chmod +x ~/pypush_reregister.sh
```
2. Execute the script
```./pypush_reregister.sh```

# Number reregistration option 2, registration using crontab
Put the following in a text file and save as `pypush_reregister.sh` in your home directory:
```
#!/bin/bash
cd ~/pypush
source ~/.venv/pypush/bin/activate
python ./demo.py --cronreg
```
1. Make the reregistration script executable:
```
chmod +x ~/pypush_reregister.sh
```
2. To automatically reregister every 30 minutes, execute the following:
```crontab -e
```
3. Add the following to your crontab file, replacing "user" with your username:
```
*/25 * * * * ~/pypush_reregister.sh > ~/pypush_log.out
```

***Please note:*** This last script is the script you will be running continuously. We recommend every 30 minutes.

### Good to Know

You will have to reregister your number every so often. This can last anywhere between 10 minutes to 48 hours, and *usually* the longer you run the script, the longer it takes to deregister. We may implement a feature to automatically detect deregistration in the future.

If you ever have any type of error, delete the config.json file and run steps 3-4 again. *This is really important.*

# Issues
This is still in the development stage, so expect issues and bugs. Here is a list of possible errors:

### Timeout waiting for response from gateway
This means it took too long for Apple to respond from the gateway number, PNRgateway is not sending the message to the correct gateway, or the response is in an incorrect encoding. This is common, please reach out for help.

### Connection Closed
This means the app crashed or could not parse the response data from the gateway. This is also common, and a recent bug has caused this error to happen excessively with non-Verizon carriers.

### Failed to resolve host
This error occurs when you are not connected to the same network, the all is closed, or you are not using the correct IP.

### Automatic gateway detection failed
This is because PNRgateway could not detect the correct gateway corresponding to your carrier. Please report this issue if you find it. To fix this issue, when you are on step 1 of number registration, append `--gateway [number]` after the `--ip` argument, and replace `number` with the gateway number. *(You can find your gateway number [here](https://discord.com/channels/1130633272595066880/1130990221920575618/1154069380699791470))*

### Failed to load the dynamic library
This is a Unicorn error. We do not yet know exactly what causes this error, but on MacOS try to run `sudo brew install unicorn`. This error usually occurs in MacOS VMs.

### Failed to register
Delete `config.json` and retry.

**If you encounter any other errors, please try to find answers online for help.**

# Resources
- [IDS and APNs error codes](https://discord.com/channels/1130633272595066880/1130990221920575618/1153062573533577246)
- [Rustpush](https://github.com/TaeHagen/rustpush)
- [PNRgateway repo](https://github.com/JJTech0130/PNRGatewayClientV2)
- [Carrier gateway list](https://discord.com/channels/1130633272595066880/1130990221920575618/1154069380699791470)
- [Beeper install](https://www.beeper.com/download)
- [Beeper signup](https://airtable.com/appSlLTU0QBt8EBZ2/shrYWTCBhNCUKU9iv)
