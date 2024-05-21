> [!WARNING]
> `pypush` is undergoing a major rewrite. The current version is not stable and may not work as expected. Many features have been temporarily removed.
>
> Versioning starts at 2.0.0 due to conflicts with the original package to have the `pypush` name. Do not expect stability until 3.0.0.

# pypush
`pypush` was originally a POC demo of my recent iMessage reverse-engineering.
It is now being developed into a community library aiming to cover all of Apple's internal API surface.

Currently, the rewritten version supports using the client side of Apple's internal APNs API, meaning it can activate as an
Apple device and receive push notifications. Stay tuned for future updates as we bring back the iMessage API and more!

`pypush` is completely platform-independent, though it may require device identifiers to use some APIs.

## Installation
Simple installation:
```bash
pip install pypush[cli]
```
Editable installation (for development):
```bash
git clone https://github.com/JJTech0130/pypush
cd pypush
pip install -e .
```

## Licensing
This project is licensed under the terms of the [SSPL](https://www.mongodb.com/licensing/server-side-public-license)

This project has been purchased by [Beeper](https://github.com/beeper), please contact them with any questions about licensing.
