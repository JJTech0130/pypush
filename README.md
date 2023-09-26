# pypush | sms-registration
`pypush` is a POC demo of my recent iMessage reverse-engineering.
It can currently register as a new device on an Apple ID, set up encryption keys, and ***send and receive iMessages*** as well as ***registering your phone number***!

This branch of `pypush` is a work in progress implementation of registering your phone number to iMessage.

## Installation
1. `git clone -b sms-registration https://github.com/beeper/pypush`
2. `pip3 install -r requirements.txt`
3. `python3 ./demo.py --phone IP`

## Operation
In order to use the SMS-registration branch, [PNRGateway](https://github.com/JJTech0130/PNRGatewayClientV2) must be installed on your android device. 
Once this is done, you must grant the app SMS permision, this is essential for this to work.

After this is done, make sure your computer and android device are connected to the same network. The PNRGateway app should now show an IP that starts with either of the following; `192.168.x.x`, `172.16.x.x`. In rare cases your IP may be different. 

After this is done, return back to your computer that has pypush cloned. You will need to run `python3 demo.py --phone 192.168.x.x`. Replace `192.168.x.x` with the IP seen on the PNRGateway app. Once this command is run, the phone number associated with your phone will be registered with iMessage.

pypush will then ask you to sign into your Apple account for (SOME REASON PLEASE FILL IN)

Once all this is done, your phone number should stay registered for around 2 hours or so. After this time, it is recomended to set up a sript that runs `python3 demo.py --register` every 30 minutes in order to keep your phone number registered. 

## Troubleshooting
If you have any issues, please join [the Discord](https://discord.gg/BVvNukmfTC) and ask for help.

## Licensing
This project is licensed under the terms of the [SSPL](https://www.mongodb.com/licensing/server-side-public-license). Portions of this project are based on [macholibre by Aaron Stephens](https://github.com/aaronst/macholibre/blob/master/LICENSE) under the Apache 2.0 license.

If you would like to use all or portions of this project in a commercial produce (without releasing source code), we are open to contacts about possible dual-licensing terms.