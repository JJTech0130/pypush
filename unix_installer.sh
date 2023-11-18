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
    echo "Installing dependencies: cmake and pkgconfig"
    sudo wget -O /usr/local/bin/pacapt https://github.com/icy/pacapt/raw/ng/pacapt
    sudo chmod 755 /usr/local/bin/pacapt
    sudo ln -sv /usr/local/bin/pacapt /usr/local/bin/pacman || true
    sudo /usr/local/bin/pacapt -S cmake pkg-config git
    echo "Removing temporary files"
    sudo rm /usr/local/bin/pacapt
    sudo rm /usr/local/bin/pacman 
else
	echo "Unknown operating system: $OS_NAME"
fi

# Create a virtual environment
mkdir -p ~/.venv
python3 -m venv ~/.venv/pypush
source ~/.venv/pypush/bin/activate

# Clone the repo
cd ~
git clone -b sms-registration https://github.com/beeper/pypush
cd pypush

# Install dependencies
pip install -r requirements.txt

# Prompt the user for the IP address of their phone.
read -p "Enter the IP address of your phone(displayed in the Android helper app): " PHONEIP

# Execute the `python demo.py` script with the phone IP address passed as a parameter.
python3 demo.py --phone $PHONEIP

# Create a reregistration script
cat > reregister.sh <<EOF
#!/bin/bash
cd ~/pypush
source ~/.venv/pypush/bin/activate
while true
do
	python3 ./demo.py --daemon
# If it disconnects, wait 5 minutes before reconnecting to avoid spamming servers
  	sleep 300
done
EOF

# Make the file executable
chmod +x reregister.sh
