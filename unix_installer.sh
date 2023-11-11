#!/bin/bash

mkdir -p ~/.venv
python3.10 -m pypush ~/.venv
source ~/.venv/pypush/bin/activate

# Clone the repo
git clone -b sms-registration https://github.com/beeper/pypush
cd pypush

# Change directories to the repository.
cd ~/pypush

# Prompt the user for the IP address of their phone.
read -p "Enter the IP address of your phone: " phoneIp

# Execute the `python demo.py` script with the phone IP address passed as a parameter.
python demo.py --phone $phoneIp

# Create a reregistration script
cat > reregister.sh <<EOF
#!/bin/bash
cd ~/pypush
source ~/.venv/pypush/bin/activate
python ./demo.py --cronreg
EOF

# Make the file executable
chmod +x reregister.sh

# Add a crontab entry to run every 15 minutes and check registration status
crontab -l | { cat; echo "*/15 * * * * ~/pypush/reregister.sh >> /dev/null 2&>1"; } | crontab -