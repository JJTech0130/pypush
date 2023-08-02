# pypush
`pypush` is a POC demo of my recent iMessage reverse-engineering.
It can currently register as a new device on an Apple ID, set up encryption keys, and ***send and receive iMessages***!

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

Once it loads, it should prompt you with `>>`. Type `help` and press enter for a list of supported commands.

## Special Notes
### Unicorn dependency
`pypush` currently uses the Unicorn CPU emulator and a custom MachO loader to load a framework from an old version of macOS,
in order to call some obfuscated functions.

This is only necessary during initial registration, so theoretically you can register on one device, and then copy the `config.json`
to another device that doesn't support the Unicorn emulator. Or you could switch out the emulator for another x86 emulator if you really wanted to.

### Public key caching
iMessage will cache public keys. If you get decryption errors in pypush or can only send and not receive messages from another device,
try logging out and back into iMessage on that device, forcing it to refresh it's key cache. Alternatively, you can wait and the cache should
expire eventually.

## Licensing
This project is licensed under the terms of the [SSPL](https://www.mongodb.com/licensing/server-side-public-license). Portions of this project are based on [macholibre by Aaron Stephens](https://github.com/aaronst/macholibre/blob/master/LICENSE) under the Apache 2.0 license.

If you would like to use all or portions of this project in a commercial produce (without releasing source code), we are open to contacts about possible dual-licensing terms.