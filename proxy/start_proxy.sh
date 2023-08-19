#!/usr/bin/env bash

set -euo pipefail

err() {
	echo -e "\e[31m[!]\e[0m ${1}" 1>&2
}

inf() {
	echo -e "\e[34m[*]\e[0m ${1}"
}

leave() {
	[ -f /etc/hosts.bak ] && { inf "Fixing /etc/hosts..." && sudo mv /etc/hosts.bak /etc/hosts; }

	[ -z ${lldb_pid+x} ] || { inf "Killing attached lldb..." && { sudo kill "$lldb_pid" 2>/dev/null || :; }; }
	[ -z ${mitm_pid+x} ] || { inf "Killing mitmweb..." && { kill "$mitm_pid" 2>/dev/null || :; }; }
	[ -z ${proxy_pid+x} ] || { inf "Killing proxy..." && { kill "$proxy_pid" 2>/dev/null || :; }; }

	cd "$old_dir" || :

	exit 0
}

[[ "$(uname)" != "Darwin" ]] && { err "This can only be run on macOS" && exit 1; }

old_dir="$(pwd)"
root_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
full_dir="$root_dir"
[[ "$old_dir" == "$root_dir" ]] && root_dir="."

trap 'leave' INT ERR

proxy_dir="${root_dir}"

inf "Setting up \e[1mhosts.proxy\e[0;34m..."

hosts_proxy="${proxy_dir}/hosts.proxy"
cat /etc/hosts > "$hosts_proxy"
python3 "${proxy_dir}/hosts.py" >> "$hosts_proxy"

echo -e "\e[32m[?]\e[0;1m ${hosts_proxy}\e[0m must be copied over to /etc/hosts. Would you like us to do that for you? [y/n]"
read -rn1 answer
if [[ "${answer,,}" == "y" ]] 
then
	inf "Backing up /etc/hosts to /etc/hosts.bak and copying ${hosts_proxy} to /etc/hosts"
	sudo cp /etc/hosts /etc/hosts.bak
	sudo cp "$hosts_proxy" /etc/hosts
fi

lldb_commands="${proxy_dir}/lldb_commands.txt"
cat << EOF > "$lldb_commands"
breakpoint set -n "SecTrustEvaluateWithError" -C "thread return 1" -C "c"
c
EOF

inf "Attaching to lldb..."
env TERM=xterm-256color sudo lldb -p $(pgrep apsd) -s "$lldb_commands" >/dev/null &
lldb_pid=$!

cat << EOF > "${proxy_dir}/imessage_proxy.pac"
// https://en.wikipedia.org/wiki/Proxy_auto-config for reference
function FindProxyForURL(url, host) {
  // to redirect apns tcp traffic
  if (shExpMatch(host, '*-courier.push.apple.com')) {
    // this should redirect it to mitmproxy if it's running.
	// should 127.0.0.1:8080 fail to respond, it should just forward it
    return 'PROXY 127.0.0.1:8080; DIRECT';
  }

  // to redirect ids stuff
  if (shExpMatch(host, '*ess.apple.com')) {
    return 'PROXY 127.0.0.1:8080; DIRECT';
  }

  // for everything else, just forward it
  return 'DIRECT'
}
EOF

inf "Setting up proxy auto-config..."
networksetup -setautoproxyurl Wi-Fi "file://${full_dir}/imessage_proxy.pac"

inf "Starting up mitmweb..."
mitmweb &
mitm_pid=$!

inf "Running apns proxy..."
python3 "${proxy_dir}/proxy.py" &
proxy_pid=$!

# need to give the proxy a second to start up or it yells at us
sleep 1

inf "Restarting wifi to force apsd to reconnect..."
networksetup -setairportpower en0 off
networksetup -setairportpower en0 on

while true; do read -rn1 _; done