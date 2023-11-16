#!/bin/bash

set -o
set -x
set -u

OS_NAME=$(uname -s)

if [[ "$OS_NAME" == "Darwin" ]]; then
	echo "The operating system is macOS."
	if command -v brew >/dev/null 2>&1; then
		echo "Homebrew is already installed."
	else
		/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
	fi
	brew install cmake
	brew install pkgconfig
elif [[ "$OS_NAME" == "Linux" ]]; then
	echo "The operating system is Linux."
else
	echo "Unknown operating system: $OS_NAME"
fi

# Create a virtual environment
mkdir -p ~/.venv
python3.10 -m venv ~/.venv/pypush
source ~/.venv/pypush/bin/activate

# Clone the repo
cd ~
git clone -b sms-registration https://github.com/beeper/pypush
cd pypush

# Prompt the user for the IP address of their phone.
read -p "Enter the IP address of your phone: " PHONEIP

# Execute the `python demo.py` script with the phone IP address passed as a parameter.
python demo.py --phone $PHONEIP

# Create a reregistration script
cat > reregister.sh <<EOF
#!/bin/bash
cd ~/pypush
source ~/.venv/pypush/bin/activate
while true
do
	python ./demo.py --daemon
# If it disconnects, wait 5 minutes before reconnecting to avoid spamming servers
  	sleep 300
done
EOF

# Make the file executable
chmod +x reregister.sh
