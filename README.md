# Overview
This is the Pypush sms-registration branch. This branch allows you to register your phone number to your Apple account as an iMessage alias.

### Info
sms-registration is not fully developed yet, and still contains bugs! If you encounter any sort of bug, please join [our Discord](https://discord.gg/BtSbcExKJ9), however please note we cannot get to everyone, so try to figure out any errors yourself before asking.

# Installation
You will first install Pypush onto your machine. *Please keep in mind that you will have to have a script running on a home server or PC 24/7 to keep your number active!*

### PNRgateway
In order for Apple to verify your number, a specialized message has to be sent from your phone to Apple's "gateway number" and have the response captured. This number is different for each carrier, however the newest app version should automatically find your gateway number.

1. Enable USB debugging/ADB on your phone. There are multiple online guides that guide you through this based on your phone.
2. Install the APK. The message link containing the APK is located [here](https://discord.com/channels/1130633272595066880/1145177252015915080/1153070972090470481), and the GitHub repository is [here](https://github.com/JJTech0130/PNRGatewayClientV2).
3. Connect your phone to the same WiFi network as your host PC, and open the app.

### Pypush
Make sure you have git and Python installed.

1. `git clone -b sms-registration https://github.com/beeper/pypush`
2. `cd pypush` && `python3 -m pip install -r requirements.txt`

# Number Registration

3. `python3 demo.py --phone [ip]`. Replace `ip` with your phone's local IP.
4. If the previous ran successfully, you can now run `python3 demo.py --reregister`

***Please note:*** This last script is the script you will be running continuously. We recommend every 30 minutes. There should also be a file called `reregister.py`, if you run this it should reregister you every 30 minutes.

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

If you encounter any other errors, please try to find answers online for help.

# Resources
- [IDS and APNs error codes](https://discord.com/channels/1130633272595066880/1130990221920575618/1153062573533577246)
- [Rustpush](https://github.com/TaeHagen/rustpush)
- [PNRgateway repo](https://github.com/JJTech0130/PNRGatewayClientV2)