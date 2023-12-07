#!/data/data/com.termux/files/usr/bin/bash

set -o pipefail

die() {
	[ $# -eq 0 ] || echo >&2 "ERROR: " "$@"
	exit 1
}

# verify we're on Android (though the #! line at the top will only work in a termux terminal anyway)
[[ "$(uname -o)" == "Android" ]] || die "This installer only works when run on Android"

set -x
# make sure all our existing pkgs are updated
pkg up || die "Updating all packages"

# install things from the pkg repo
#  python-cryptography:
#      Has to be installed from pkg rather than from pip3 because installing it from pip3
#      doesn't find a pre-built binary, and the termux Rust toolchain for the fallback
#      building it from source doesn't work without tons of effort. That's why it's pre-packaged
#      by pkg.
#  build-essential:
#      The python unicorn package doens't have a compatible pre-build binary version in PyPi
#      so it will build it from source on-demand.  That requires the build-essential tools,
#      like gcc, cmake, etc.
pkg install \
	termux-tools \
	termux-api \
	python \
	python-cryptography \
	python-pip \
	git \
	build-essential \
	binutils
  || die "Installing necessary packages"

set +x

# verify the termux-api actually works. if 
timeout -s 9 30s termux-job-scheduler -p \
	|| die "Unable to use termux API, verify the it and the Termux app are both installed and both from F-Droid (not Google Play)"

# Because we can't build the python 'cryptography' library on Termux, we can't install it in a venv.
# That means we have to install all the packages directly on the host instead.

# Clone the repo
cd $HOME
set -x
git clone -b sms-registration https://github.com/JJTech0130/pypush \
	|| die
set +x
cd pypush

set -x
# Install dependencies
pip3 install -r requirements.txt \
	|| die
# on Termux, this isn't automatically installed with pip so it's not provided by pkg like the requirements.txt expects
pip3 install setuptools \
	|| die
set +x

read -p "Make sure the PNRGateway app ("Pypush SMS Registration Hellper") is running in split screen, then press Enter" JUNK

remove_config_json() {
	rm -f $HOME/pypush/config.json
}
export -f remove_config_json

if [ -e "$HOME/pypush/config.json" ]; then
	read -p "Remove existing config.json file? (Y/n) " REMOVE_IT
	# lowercase it and drop anything that's not 'y' or 'n'
	REMOVE_IT=$(echo -n "$REMOVE_IT" | tr '[:upper:]' '[:lower:]' | tr -dc 'yn' )
	if [[ "$REMOVE_IT" != "n" ]]; then
		echo "Removing prior config.json"
		set -x
		rm $HOME/pypush/config.json
		set +x
	fi
fi

# set a trap to remove the config.json file if the next step fails
trap "remove_config_json" EXIT

set -x
# Execute the `python demo.py` script.  Since we're in Termux, the app is on localhost relative to us.
# This is user-interactive
python3 demo.py --phone 127.0.0.1 \
	|| die "If registering with the number failed, it might be a temporary carrier issue, but confirm the registration number for your carrier was used from this list: https://discord.com/channels/1130633272595066880/1130990221920575618/1154069380699791470"
set +x
trap "" EXIT

echo "Creating reregistration.sh" script

# Create a reregistration script
cat > reregister.sh <<EOF
#!/data/data/com.termux/files/usr/bin/bash
cd $HOME/pypush
# When unlocking, or powering on the phone, the job may trigger multiple times.
# Protect it from parallel execution (sort of) with a simple flag file existence check.
flag=reregistering.flag
if [ ! -e \$flag ]; then
	touch \$flag
	# use --cronreg so it only reregisters if it's going to expire in the next 60 minutes
	python3 ./demo.py --cronreg
	ret=\$?
	rm \$flag
	exit \$ret
fi
EOF
[ $? -eq 0 ] || die "Creating reregistrater.sh"

# Make the file executable
chmod +x reregister.sh \
	|| die "Adding execute permissions to regristrater.sh"

# Setup the reregistration as an Android system job.
job_reg_args=()
job_reg_args+=("--script" "$(pwd)/reregister.sh")
# The minimum period allowed is 15 min (900000 ms).
job_reg_args+=("--period-ms" "900000")
# Even if the battery is low, we need to re-register to maintain the phone number link.
job_reg_args+=("--battery-not-low" "false")
# Make it permanent across reboots too.
job_reg_args+=("--persisted" "true")

echo "Checking for prior scheduled regregistration job"

# in case the scheduled job was already setup to run our scrip previously,
# query the termux job scheduler, grep for our script, split on : taking the first, then split on spaces taking the third
# to get the job ID(s) from the pending list.  Take only the first job if there's more than one, and strip the newline
# so we have just the number.  If any of this fails, just return blank with no newline.
existing_job_id=$(termux-job-scheduler -p | grep "reregister\.sh" | cut -d ':' -f1 | cut -d ' ' -f3 | head -n1 | tr -d '\n' || echo -n "")

if [ -n "$existing_job_id" ]; then
	echo "Scheduled job for reregistration already exists with ID: $existing_job_id"
	job_reg_args+=("--job-id" "$existing_job_id")
fi

echo "Scheduling reregistration job"
set -x
# schedule it, or update the pre-existing scheduled job
termux-job-scheduler "${job_reg_args[@]}" \
	|| die "Scheduling re-registration as an Android system job"
set +x