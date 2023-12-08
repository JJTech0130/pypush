# pypush
`pypush` is a POC demo of my recent iMessage reverse-engineering.
It can currently register as a new device on an Apple ID, set up encryption keys, and ***send and receive iMessages***!

`pypush` is completely platform-independent, and does not require a Mac or other Apple device to use!

## Project Setup Instructions
1.Clone Repository
To get started with the project, follow these simple steps to set up your development environment:

git clone https://github.com/JJTech0130/pypush

2.Navigate to Project Directory
Change your current working directory to the cloned repository:

cd pypush

3.Install Dependencies
Install the required dependencies using pip3 and the provided requirements.txt file:

pip3 install -r requirements.txt

4.Run Demo
Execute the demo script to see the project in action:

python3 ./demo.py

## Troubleshooting
If you have any issues, please join [the Discord](https://discord.gg/BVvNukmfTC) and ask for help.

## Operation
`pypush` will generate a `config.json` in the repository when you run demo.py. DO NOT SHARE THIS FILE.
It contains all the encryption keys necessary to log into you Apple ID and send iMessages as you.

Once it loads, it should prompt you with `>>`. Type `help` and press enter for a list of supported commands.

## Special Notes
### Unicorn dependency
`pypush` currently uses the Unicorn CPU emulator and a custom MachO loader to load a framework from an old version of macOS,
in order to call some obfuscated functions.

This is only necessary during initial registration, so theoretically you can register on one device, and then copy the `config.json`
to another device that doesn't support the Unicorn emulator. Or you could switch out the emulator for another x86 emulator if you really wanted to.

## "data.plist" and Mac serial numbers
This repository contains a sample [`data.plist`](https://github.com/JJTech0130/pypush/blob/main/emulated/data.plist), which contains the serial number and several other identifiers from a real Mac device. If you run into issues related to rate-limiting or messages failing to deliver, you may regenerate this file by cloning [nacserver](https://github.com/JJTech0130/nacserver) and running `build.sh` on a non-M1 Mac. It should place the generated file in the current directory, which you can then copy to the emulated/ folder in pypush.

## Licensing
This project is licensed under the terms of the [SSPL](https://www.mongodb.com/licensing/server-side-public-license). Portions of this project are based on [macholibre by Aaron Stephens](https://github.com/aaronst/macholibre/blob/master/LICENSE) under the Apache 2.0 license.

This project has been purchased by [Beeper](https://github.com/beeper), please contact them with any questions about licensing.
