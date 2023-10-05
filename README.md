# pypush
`pypush` is a POC demo of my recent iMessage reverse-engineering.
It can currently register as a new device on an Apple ID, set up encryption keys, and ***send and receive iMessages***!

<<<<<<< HEAD
sms-registration is not fully developed yet, and still contains bugs! If you encounter any sort of bug, please join [our Discord](https://discord.gg/BtSbcExKJ9), however please note we cannot get to everyone, so try to figure out any errors yourself before asking.

***Please note:*** You will have to use a client to send messages from your phone. We recommend [Beeper](https://www.beeper.com/), which is the best solution to keep all your chat apps inside one place, including iMessage! You can also use [BlueBubbles](https://www.beeper.com/) (which requires you to have a server Mac running 24/7) or [Sunbird](https://www.sunbirdapp.com/) (which is closed source and requires you to be a beta tester). Beeper is completely free and easy to use, and comes packed with multiple features that reivals native apps. Beeper is currently in the process of removing the waitlist, so you will have to use an invite link shared to you in order to skip the waitlist until this change is made.

# Installation
You will first install Pypush onto your machine. *Please keep in mind that you will have to have a script running on a home server or PC 24/7 to keep your number active! See below for instructions.*

### PNRgateway
In order for Apple to verify your number, a specialized message has to be sent from your phone to Apple's "gateway number" and have the response captured. This number is different for each carrier, however the newest app version should automatically find your gateway number. If PNRgateway cannot find your gateway number, see below for help.

1. Enable USB debugging/ADB on your phone. There are multiple online guides that guide you through this based on your phone.
2. Install the APK. The message link containing the APK is located [here](https://discord.com/channels/1130633272595066880/1145177252015915080/1153070972090470481), and the GitHub repository is [here](https://github.com/JJTech0130/PNRGatewayClientV2).
3. Grant SMS permissions. This will be in the app info page, and on the newer version, there should be a button in the app that does this for you.
4. Connect your phone to the same WiFi network as your host PC, and open the app.
=======
`pypush` is completely platform-independent, and does not require a Mac or other Apple device to use!

## Installation
It's pretty self explanatory:
1. `git clone https://github.com/JJTech0130/pypush`
2. `pip3 install -r requirements.txt`
3. `python3 ./demo.py`

## Troubleshooting
If you have any issues, please join [the Discord](https://discord.gg/BVvNukmfTC) and ask for help.

## Operation
`pypush` will generate a `config.json` in the repository when you run demo.py. DO NOT SHARE THIS FILE.
It contains all the encryption keys necessary to log into you Apple ID and send iMessages as you.
>>>>>>> parent of 902c52c (Update README.md)

Once it loads, it should prompt you with `>>`. Type `help` and press enter for a list of supported commands.

<<<<<<< HEAD
1. `git clone -b sms-registration https://github.com/beeper/pypush`
2. `cd pypush` ,  `python3 -m pip install -r requirements.txt`
=======
## Special Notes
### Unicorn dependency
`pypush` currently uses the Unicorn CPU emulator and a custom MachO loader to load a framework from an old version of macOS,
in order to call some obfuscated functions.
>>>>>>> parent of 902c52c (Update README.md)

This is only necessary during initial registration, so theoretically you can register on one device, and then copy the `config.json`
to another device that doesn't support the Unicorn emulator. Or you could switch out the emulator for another x86 emulator if you really wanted to.

<<<<<<< HEAD
1. `python3 demo.py --phone [ip]`. Replace `ip` with your phone's local IP. *(Usually this starts with `192.168.x.x`, however it can also start with `172` or `10`.)*
2. If the previous ran successfully, you can now run `python3 demo.py --reregister`

***Please note:*** This last script is the script you will be running continuously. We recommend every 30 minutes.

### Automatic registration
There should also be a file called `reregister.py`, if you run this it should reregister you every 30 minutes. You can edit this file to rerun at any other interval. You can also use a cronjob to do this task for you in a more streamlined way if you are more familiar with IT.

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
=======
### Public key caching
iMessage will cache public keys. If you get decryption errors in pypush or can only send and not receive messages from another device,
try logging out and back into iMessage on that device, forcing it to refresh it's key cache. Alternatively, you can wait and the cache should
expire eventually.

## Licensing
This project is licensed under the terms of the [SSPL](https://www.mongodb.com/licensing/server-side-public-license). Portions of this project are based on [macholibre by Aaron Stephens](https://github.com/aaronst/macholibre/blob/master/LICENSE) under the Apache 2.0 license.

If you would like to use all or portions of this project in a commercial produce (without releasing source code), we are open to contacts about possible dual-licensing terms.
>>>>>>> parent of 902c52c (Update README.md)
