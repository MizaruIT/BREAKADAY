#!/bin/bash
# Author: The BREAKADAY Project
###
### THE SECTION
# 1) CREATION ENVIRONMENT (BREAKADAY)
# exemples : 
# - creation_environment_breakaday
# 2) DOWNLOAD UTILITIES 
# exemples : 
# - For AD : package_base, package_advanced_ad, package_base_breakaday, package_exploit_ad, package_wordlists, package_cracking, package_network, etc.


RED='\033[1;31m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
NOCOLOR='\033[0m'

### Support functions

function colorecho () {
  echo -e "${BLUE}[BREAKADAY] $*${NOCOLOR}"
}

function criticalecho () {
  echo -e "${RED}[BREAKADAY ERROR] $*${NOCOLOR}" 2>&1
  exit 1
}

function criticalecho-noexit () {
  echo -e "${RED}[BREAKADAY ERROR] $*${NOCOLOR}" 2>&1
}

function add-aliases() {
  colorecho "Adding aliases for: $*"
  # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
  grep -vE "^\s*$" "/root/sources/zsh/aliases.d/$*" >> /opt/.breakaday_aliases
}

function add-history() {
  colorecho "Adding history commands for: $*"
  # Removing add empty lines and the last trailing newline if any, and adding a trailing newline.
  grep -vE "^\s*$" "/root/sources/zsh/history.d/$*" >> ~/.zsh_history
}

function add-test-command() {
  colorecho "Adding build pipeline test command: $*"
  echo "$*" >> "/.breakaday/build_pipeline_tests/all_commands.txt"
}

function add-to-list() {
  echo $1 >> "/.breakaday/installed_tools"
}

function fapt() {
  colorecho "Installing apt package(s): $*"
  apt-get install -y --no-install-recommends "$@" || exit
}

function fapt-noexit() {
  # This function tries the same thing as fapt but doesn't exit in case something's wrong.
  # Example: a package exists in amd64 but not arm64. I didn't find a way of knowing that beforehand.
  colorecho "Installing (no-exit) apt package(s): $*"
  apt-get install -y --no-install-recommends "$*" || echo -e "${RED}[EXEGOL ERROR] Package(s) $* probably doesn't exist for architecture $(uname -m), or no installation candidate was found, or some other error...${NOCOLOR}" 2>&1
}

### Setup, and special tool install functions

function post_install_clean() {
  # Function used to clean up post-install files
  colorecho "Cleaning..."
  updatedb
  rm -rfv /tmp/*
  echo "# -=-=-=-=-=-=-=- YOUR COMMANDS BELOW -=-=-=-=-=-=-=- #" >> ~/.zsh_history
}

function update() {
  colorecho "Updating, upgrading, cleaning"
  echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
  apt-get -y update && apt-get -y install apt-utils dialog && apt-get -y upgrade && apt-get -y autoremove && apt-get clean
}

function filesystem() {
  colorecho "Preparing filesystem"
  mkdir -p /opt/tools/
  mkdir -p /opt/tools/bin/
  mkdir -p /data/
  mkdir -p /var/log/breakaday
  mkdir -p /.breakaday/build_pipeline_tests/
  touch /.breakaday/build_pipeline_tests/all_commands.txt
}

function set_go_env(){
  colorecho "Setting environment variables for installation"
  export GO111MODULE=on
  export PATH=$PATH:/usr/local/go/bin:/root/.local/bin
}

function deploy_breakaday() {
  colorecho "Installing breakaday things"
  # Moving breakaday files to /
  mkdir /var/log/breakaday
  # Creating environment
  filesystem
  creation_environment_breakaday
}

#######################
# 1) GLOBAL INSTALLATION
#######################
### Tool installation functions
function install_ohmyzsh() {
  colorecho "Installing oh-my-zsh, config, history, aliases"
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
  cp -v /root/sources/zsh/history ~/.zsh_history
  cp -v /root/sources/zsh/aliases /opt/.breakaday_aliases
  cp -v /root/sources/zsh/zshrc ~/.zshrc
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/zsh-users/zsh-autosuggestions
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/zsh-users/zsh-syntax-highlighting
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/zsh-users/zsh-completions
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/agkozak/zsh-z
  git -C ~/.oh-my-zsh/custom/plugins/ clone https://github.com/lukechilds/zsh-nvm
  zsh -c "source ~/.oh-my-zsh/custom/plugins/zsh-nvm/zsh-nvm.plugin.zsh" # this is needed to start an instance of zsh to have the plugin set up
}

function install_curl() {
  colorecho "Installing curl"
  fapt curl
  add-history curl
  add-to-list "curl,https://curl.se/,A command-line tool for transferring data using various protocols"
}

function install_tmux() {
  colorecho "Installing tmux"
  fapt tmux
  cp -v /root/sources/tmux/tmux.conf ~/.tmux.conf
  touch ~/.hushlogin
  add-to-list "tmux,https://github.com/tmux/tmux,a terminal multiplexer for Unix-like operating systems."
}

function install_grc() {
  colorecho "Installing and configuring grc"
  apt-get -y install grc
  cp -v /root/sources/grc/grc.conf /etc/grc.conf
  add-aliases grc
  add-to-list "grc,https://github.com/garabik/grc,Colorize logfiles and command output."
}
function install_ultimate_vimrc() {
  colorecho "Installing The Ultimate vimrc"
  git clone --depth=1 https://github.com/amix/vimrc.git ~/.vim_runtime
  sh ~/.vim_runtime/install_awesome_vimrc.sh
  add-to-list "ultimate,https://github.com/amix/vimrc.git,Vim in steroids."
}

function install_openvpn() {
  fapt openvpn                    # Instal OpenVPN
  fapt openresolv                 # Dependency for DNS resolv.conf update with OpenVPN connection (using script)

  # Fixing openresolv to update /etc/resolv.conf without resolvectl daemon (with a fallback if no DNS server are supplied)
  line=$(($(grep -n 'up)' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
  sed -i ${line}'i cp /etc/resolv.conf /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf

  line=$(($(grep -n 'resolvconf -a' /etc/openvpn/update-resolv-conf | cut -d ':' -f1) +1))
  sed -i ${line}'i [ "$(resolvconf -l "tun*" | grep -vE "^(\s*|#.*)$")" ] && /sbin/resolvconf -u || cp /etc/resolv.conf.backup /etc/resolv.conf' /etc/openvpn/update-resolv-conf
  line=$(($line + 1))
  sed -i ${line}'i rm /etc/resolv.conf.backup' /etc/openvpn/update-resolv-conf
  add-test-command "openvpn --version"
}

function install_dnsutils() {
  colorecho "Installing dnsutils"
  fapt dnsutils
  add-history dnsutils
  add-to-list "dnsutils,https://manpages.debian.org/jessie/dnsutils/dig.1.en.html,Provides various tools for querying DNS servers"
}
function install_samba() {
  colorecho "Installing samba"
  fapt samba
  add-history samba
  add-to-list "samba,https://github.com/samba-team/samba,Samba is an open-source implementation of the SMB/CIFS networking protocol"
}

function install_ssh() {
  colorecho "Installing ssh"
  fapt ssh
  add-history ssh
  add-to-list "ssh,https://github.com/openssh/openssh-portable,SSH (Secure Shell) is a cryptographic network protocol for secure data communication"
}

function install_snmp() {
  colorecho "Installing snmp"
  fapt snmp
  add-history snmp
  add-to-list "snmp,https://doc.ubuntu-fr.org/snmp,SNMP is a protocol for network management"
}

function install_chromium() {
  fapt chromium
  add-test-command "chromium --version"
  add-to-list "chromium,https://github.com/chromium/chromium,Open-source web browser project from Google."
}

function install_firefox() {
  colorecho "Installing firefox"
  fapt firefox-esr
  mkdir /opt/tools/firefox
  mv /root/sources/firefox/* /opt/tools/firefox/
  python3 -m pip install -r /opt/tools/firefox/requirements.txt
  python3 /opt/tools/firefox/setup.py
  add-test-command "file /root/.mozilla/firefox/*.breakaday"
  add-test-command "firefox --version"
}

### Programming language installation functions
function install_nvm() {
  colorecho "Installing nvm (in zsh context)"
  zsh -c "source ~/.zshrc && nvm install node"
  add-to-list "nvm,https://github.com/nvm-sh/nvm,Node Version Manager - Simple bash script to manage multiple active node.js versions."
}

function install_yarn() {
  colorecho "Installing yarn"
  curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add -
  echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
  apt update
  apt install -y yarn
  add-to-list "yarn,https://yarnpkg.com,A package manager for JavaScript"
}


function install_python-pip() {
  colorecho "Installing python-pip (for Python2.7)"
  curl --insecure https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
  python get-pip.py
  rm get-pip.py
  add-test-command "pip --version"
}

function install_pipx() {
  colorecho "Installing pipx"
  python3 -m pip install pipx
  pipx ensurepath
  add-test-command "pipx --version"
  add-to-list "pipx,https://github.com/pipxproject/pipx,Execute binaries from Python packages in isolated environments"
}

function install_fzf() {
  colorecho "Installing fzf"
  git -C /opt/tools/ clone --depth 1 https://github.com/junegunn/fzf.git
  cd /opt/tools/fzf || exit
  ./install --all
  add-aliases fzf
  add-test-command "fzf --version"
  add-to-list "fzf,https://github.com/junegunn/fzf,a command-line fuzzy finder"
}

function install_php() {
  colorecho "Installing php"
  fapt php
  add-aliases php
  add-to-list "php,https://www.php.net,A popular general-purpose scripting language"
}

function install_python3() {
  colorecho "Installing python3"
  fapt python3
  add-aliases python3
  add-to-list "python3,https://www.python.org,A popular general-purpose programming language"
}

function install_rust_cargo() {
  colorecho "Installing rustc, cargo, rustup"
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  source "$HOME/.cargo/env"
  add-test-command "cargo --version"
  add-to-list "rust,https://www.rust-lang.org,A systems programming language focused on safety, speed, and concurrency"
}

function install_go(){
  colorecho "Installing go (Golang)"
  cd /tmp/ || exit
  if [[ $(uname -m) = 'x86_64' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-amd64.tar.gz
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-arm64.tar.gz
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    wget -O /tmp/go.tar.gz https://go.dev/dl/go1.20.linux-armv6l.tar.gz
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  add-test-command "go version"
  add-to-list "go,https://golang.org/doc/install,A programming language often used to create command line tools"
}

##########################
# 2) BREAKADAY INSTALLATION
##########################
# GENERAL
function install_dirb() {
  colorecho "Installing dirb"
  fapt dirb
  add-history dirb
  add-test-command "dirb | grep '<username:password>'"
  add-to-list "dirb,https://github.com/v0re/dirb,Web Content Scanner"
}

function install_ffuf() {
  colorecho "Installing ffuf"
  go install -v github.com/ffuf/ffuf@latest
  add-history ffuf
  add-test-command "ffuf --help"
  add-to-list "ffuf,https://github.com/ffuf/ffuf,Fast web fuzzer written in Go."
}

function install_whatweb() {
  colorecho "Installing whatweb"
  fapt whatweb
  add-test-command "whatweb --version"
  add-to-list "whatweb,https://github.com/urbanadventurer/WhatWeb,Next generation web scanner that identifies what websites are running."
}

function install_smbmap(){
  colorecho "Installing smbmap"
  git -C /opt/tools/ clone -v https://github.com/ShawnDEvans/smbmap
  cd /opt/tools/smbmap || exit
  # installing requirements manually to skip impacket overwrite
  # wish we could install smbmap in virtual environment :'(
  python3 -m pip install pyasn1 pycrypto configparser termcolor impacket
  add-aliases smbmap
  add-history smbmap
  add-test-command "smbmap --help"
  add-to-list "smbmap,https://github.com/ShawnDEvans/smbmap,A tool to enumerate SMB shares and check for null sessions"
}

function install_android-tools-adb() {
  colorecho "Installing android-tools-adb"
  fapt android-tools-adb
  add-test-command "adb --help"
  add-to-list "android-tools-adb,https://developer.android.com/studio/command-line/adb,A collection of tools for debugging Android applications"
}

# SCANNER
function install_scanner_bluegate(){
  colorecho "Installing SCANNER utilities"
  # => SCANNER/CVE/BlueGate_CVE-2020-0610
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/BlueGate_CVE-2020-0610 clone https://github.com/ly4k/BlueGate
}

function install_scanner_getgpppassword(){
  colorecho "Installing SCANNER utilities"
  # => SCANNER/CVE/GPP-Abuse_CVE-2014-1812
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/GPP-Abuse_CVE-2014-1812 clone https://github.com/ShutdownRepo/Get-GPPPassword
}


function install_scanner_printnightmare(){
  colorecho "Installing SCANNER utilities"
  # => SCANNER/CVE/PrintNightmare_CVE-2021-34527
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/PrintNightmare_CVE-2021-34527 clone https://github.com/ly4k/PrintNightmare
}

function install_scanner_samaccountnamespoofing(){
  colorecho "Installing SCANNER utilities"
  # => SCANNER/CVE/sAMAccountNameSpoofing_CVE-2021-42278
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/sAMAccountNameSpoofing_CVE-2021-42278 clone https://github.com/ly4k/Pachine
  chmod +x "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/sAMAccountNameSpoofing_CVE-2021-42278/Pachine/pachine.py"
}

function install_scanner_smbghost(){
  colorecho "Installing SCANNER utilities"
  # => SCANNER/CVE/SMBGhost_CVE-2020-0796
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796 clone https://github.com/ZecOps/SMBGhost-SMBleed-scanner
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost-SMBleed-scanner/SMBGhost-SMBleed-scanner.py"
  if ! head -n 1 "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost-SMBleed-scanner/SMBGhost-SMBleed-scanner.py" | grep -q python3; then sed -i '1 i\#!/usr/bin/env python3' "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost-SMBleed-scanner/SMBGhost-SMBleed-scanner.py"; fi
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost clone https://github.com/ly4k/SMBGhost
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost/scanner.py"
  if ! head -n 1 "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost/scanner.py" | grep -q python3; then sed -i '1 i\#!/usr/bin/env python3' "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796/SMBGhost/scanner.py"; fi
}

function install_scanner_windowsntlmtampering(){
  colorecho "Installing SCANNER utilities"
  # => SCANNER/CVE/WindowsNTLMTampering_CVE-2019-1040
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/WindowsNTLMTampering_CVE/ clone https://github.com/fox-it/cve-2019-1040-scanner
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/WindowsNTLMTampering_CVE-2019-1040/cve-2019-1040-scanner/scan.py"
}

function install_scanner_zerologon(){
  colorecho "Installing SCANNER utilities"
  #### => SCANNER/CVE/ZeroLogon_CVE-2020-1472
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/ZeroLogon_CVE-2020-1472 clone https://github.com/SecuraBV/CVE-2020-1472
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/ZeroLogon_CVE-2020-1472/CVE-2020-1472/zerologon_tester.py"
}

function install_scanner_hivenightmare(){
  colorecho "Installing SCANNER utilities"
  #### => SCANNER/LocalWindows/CVE-2021-363934
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/LocalWindows/CVE-2021-363934 clone https://github.com/pyonghe/HiveNightmareChecker
}

function install_scanner_eternalblue(){
  colorecho "Installing SCANNER utilities"
  #### => SCANNER/MS-VULNS/EternalBlue_MS17-010
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010 clone https://github.com/3ndG4me/AutoBlue-MS17-010
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/AutoBlue-MS17-010/eternal_checker.py"
  if ! head -n 1 "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/AutoBlue-MS17-010/eternal_checker.py" | grep -q python3; then sed -i '1 i\#!/usr/bin/env python3' "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/AutoBlue-MS17-010/eternal_checker.py"; fi
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/MS17-010 clone https://github.com/worawit/MS17-010
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/MS17-010/checker.py"
  if ! head -n 1 "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/MS17-010/checker.py" | grep -q python3; then sed -i '1 i\#!/usr/bin/env python3' "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010/MS17-010/checker.py"; fi
}

function install_scanner_kerberoschecksum(){
  colorecho "Installing SCANNER utilities"
  #### => SCANNER/MS-VULNS/KerberosChecksum_MS14-068
  # TO DO wget
  wget https://raw.githubusercontent.com/SpiderLabs/Responder/master/tools/FindSMB2UPTime.py -P /opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/KerberosChecksum_MS14-068
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/KerberosChecksum_MS14-068/FindSMB2UPTime.py"
  # TO DO : add packets.py from the git
}

function install_scanner_smbpipes(){
  colorecho "Installing SCANNER utilities"
  #### => SCANNER/VULNS/SMB-Pipes
  git -C /opt/tools/PENTEST-TOOLKIT/SCANNER/VULNS/SMB-Pipes/Coercer clone https://github.com/p0dalirius/Coercer
  wget https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py -P /opt/tools/PENTEST-TOOLKIT/SCANNER/VULNS/SMB-Pipes/PrinterBug/
  chmod 755 "/opt/tools/PENTEST-TOOLKIT/SCANNER/VULNS/SMB-Pipes/PrinterBug/rpcdump.py"
}

#####################
### => BASIC TOOLS
#####################
function install_responder() {
  colorecho "Installing Responder"
  git -C /opt/tools/ clone https://github.com/lgandx/Responder
  sed -i 's/ Random/ 1122334455667788/g' /opt/tools/Responder/Responder.conf
  sed -i 's/files\/AccessDenied.html/\/opt\/tools\/Responder\/files\/AccessDenied.html/g' /opt/tools/Responder/Responder.conf
  sed -i 's/files\/BindShell.exe/\/opt\/tools\/Responder\/files\/BindShell.exe/g' /opt/tools/Responder/Responder.conf
  sed -i 's/certs\/responder.crt/\/opt\/tools\/Responder\/certs\/responder.crt/g' /opt/tools/Responder/Responder.conf
  sed -i 's/certs\/responder.key/\/opt\/tools\/Responder\/certs\/responder.key/g' /opt/tools/Responder/Responder.conf
  fapt gcc-mingw-w64-x86-64 python3-netifaces
  x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Runas.c -o /opt/tools/Responder/tools/MultiRelay/bin/Runas.exe -municode -lwtsapi32 -luserenv
  x86_64-w64-mingw32-gcc /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.c -o /opt/tools/Responder/tools/MultiRelay/bin/Syssvc.exe -municode
  cd /opt/tools/Responder || exit
  /opt/tools/Responder/certs/gen-self-signed-cert.sh
  add-aliases responder
  add-history responder
  add-test-command "responder --version"
  add-to-list "responder,https://github.com/lgandx/Responder,a LLMNR, NBT-NS and MDNS poisoner."
}

function install_crackmapexec() {
  colorecho "Installing CrackMapExec"
  # Source bc cme needs cargo PATH (rustc) -> aardwolf dep
  # TODO: Optimize so that the PATH is always up to date
  source /root/.zshrc
  git -C /opt/tools/ clone https://github.com/Porchetta-Industries/CrackMapExec.git
  python3 -m pipx install /opt/tools/CrackMapExec/
  mkdir -p ~/.cme
  [ -f ~/.cme/cme.conf ] && mv ~/.cme/cme.conf ~/.cme/cme.conf.bak
  cp -v /root/sources/crackmapexec/cme.conf ~/.cme/cme.conf
  # below is for having the ability to check the source code when working with modules and so on
  # git -C /opt/tools/ clone https://github.com/byt3bl33d3r/CrackMapExec
  cp -v /root/sources/grc/conf.cme /usr/share/grc/conf.cme
  add-aliases crackmapexec
  add-history crackmapexec
  add-test-command "crackmapexec --help"
  add-to-list "crackmapexec,https://github.com/byt3bl33d3r/CrackMapExec,Network scanner."
}

function install_searchsploit() {
  colorecho "Installing Searchsploit"
  git -C /opt/tools/ clone https://gitlab.com/exploit-database/exploitdb
  ln -sf /opt/tools/exploitdb/searchsploit /opt/tools/bin/searchsploit
  cp -n /opt/tools/exploitdb/.searchsploit_rc ~/
  sed -i 's/\(.*[pP]aper.*\)/#\1/' ~/.searchsploit_rc
  sed -i 's/opt\/exploitdb/opt\/tools\/exploitdb/' ~/.searchsploit_rc
  searchsploit -u
  add-test-command "searchsploit --help; searchsploit --help |& grep 'You can use any number of search terms'"
  add-to-list "searchsploit,https://gitlab.com/exploit-database/exploitdb,A command line search tool for Exploit-DB"
}

function install_metasploit(){
  colorecho "Installing Metasploit"
  #apt-get clean
  #zsh -c 'rm -rvf /var/lib/apt/lists/*'
  #apt-get update
  mkdir /tmp/metasploit_install
  cd /tmp/metasploit_install || exit
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
  cd /opt/tools || exit
  rm -rf /tmp/metasploit_install
  add-test-command "msfconsole --version"
  add-to-list "metasploit,https://github.com/rapid7/metasploit-framework,A popular penetration testing framework that includes many exploits and payloads"
}

#####################
### => AD TOOLS
#####################
function install_ldapdomaindump() {
  colorecho "Installing ldapdomaindump"
  python3 -m pipx install git+https://github.com/dirkjanm/ldapdomaindump
  add-history ldapdomaindump
  add-test-command "ldapdomaindump --help"
  add-to-list "ldapdomaindump,https://github.com/dirkjanm/ldapdomaindump,A tool for dumping domain data from an LDAP service"
}

function install_ldapsearch() {
  colorecho "Installing ldapsearch"
  fapt ldap-utils
  add-history ldapsearch
  add-test-command "ldapsearch --help; ldapsearch --help |& grep 'Search options'"
}

function install_ldapsearch-ad() {
  colorecho "Installing ldapsearch-ad"
  git -C /opt/tools/ clone https://github.com/yaap7/ldapsearch-ad
  cd /opt/tools/ldapsearch-ad/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases ldapsearch-ad
  add-history ldapsearch-ad
  add-test-command "ldapsearch-ad --version"
  add-to-list "ldapsearch-ad,https://github.com/yaap7/ldapsearch-ad,LDAP search utility with AD support"
}

function install_bloodhound-py() {
  colorecho "Installing and Python ingestor for BloodHound"
  git -C /opt/tools/ clone https://github.com/fox-it/BloodHound.py
  add-aliases bloodhound-py
  add-history bloodhound-py
  add-test-command "bloodhound.py --help"
  add-to-list "bloodhound-py,https://github.com/fox-it/BloodHound.py,Trust relationship analysis tool for Active Directory environments."
}

function install_neo4j() {
  colorecho "Installing neo4j"
  wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add -
  # TODO: temporary fix => rollback to 4.4 stable until perf issue is fix on neo4j 5.x
  #echo 'deb https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list
  echo 'deb https://debian.neo4j.com stable 4.4' | tee /etc/apt/sources.list.d/neo4j.list
  apt-get update
  apt-get -y install --no-install-recommends gnupg libgtk2.0-bin libcanberra-gtk-module libx11-xcb1 libva-glx2 libgl1-mesa-glx libgl1-mesa-dri libgconf-2-4 libasound2 libxss1
  apt-get -y install neo4j
  # TODO: when temporary fix is not needed anymore --> neo4j-admin dbms set-initial-password exegol4thewin
  neo4j-admin set-initial-password exegol4thewin
  mkdir -p /usr/share/neo4j/logs/
  touch /usr/share/neo4j/logs/neo4j.log
  add-aliases neo4j
  add-history neo4j
  add-test-command "neo4j version"
  add-to-list "neo4j,https://github.com/neo4j/neo4j,Database."
}

function install_bloodhound() {
  colorecho "Installing BloodHound from sources"
  git -C /opt/tools/ clone https://github.com/BloodHoundAD/BloodHound/
  mv /opt/tools/BloodHound /opt/tools/BloodHound4
  zsh -c "source ~/.zshrc && cd /opt/tools/BloodHound4 && nvm install 16.13.0 && nvm use 16.13.0 && npm install -g electron-packager && npm install && npm run build:linux"
  if [[ $(uname -m) = 'x86_64' ]]
  then
    ln -s /opt/tools/BloodHound4/BloodHound-linux-x64/BloodHound /opt/tools/BloodHound4/BloodHound
  elif [[ $(uname -m) = 'aarch64' ]]
  then
    fapt libgbm1
    ln -s /opt/tools/BloodHound4/BloodHound-linux-arm64/BloodHound /opt/tools/BloodHound4/BloodHound
  elif [[ $(uname -m) = 'armv7l' ]]
  then
    fapt libgbm1
    ln -s /opt/tools/BloodHound4/BloodHound-linux-armv7l/BloodHound /opt/tools/BloodHound4/BloodHound
  else
    criticalecho-noexit "This installation function doesn't support architecture $(uname -m)" && return
  fi
  mkdir -p ~/.config/bloodhound
  cp -v /root/sources/bloodhound/config.json ~/.config/bloodhound/config.json
  cp -v /root/sources/bloodhound/customqueries.json ~/.config/bloodhound/customqueries.json
  add-aliases bloodhound
  # TODO add-test-command
  add-to-list "bloodhound,https://github.com/BloodHoundAD/BloodHound,Active Directory security tool for reconnaissance and attacking AD environments."
}

function install_bloodhound-import() {
  colorecho "Installing bloodhound-import"
  python3 -m pipx install bloodhound-import
  add-history bloodhound-import
  add-test-command "bloodhound-import --help"
  add-to-list "bloodhound-import,https://github.com/fox-it/BloodHound.py,Import data into BloodHound for analyzing active directory trust relationships"
}

function install_bloodhound-quickwin() {
  colorecho "Installing bloodhound-quickwin"
  python3 -m pip install py2neo pandas prettytable
  git -C /opt/tools/ clone https://github.com/kaluche/bloodhound-quickwin
  add-aliases bloodhound-quickwin
  add-history bloodhound-quickwin
  add-test-command "bloodhound-quickwin --help"
  add-to-list "bloodhound-quickwin,https://github.com/kaluche/bloodhound-quickwin,A tool for BloodHounding on Windows machines without .NET or Powershell installed"
}

function install_impacket() {
  colorecho "Installing Impacket scripts"
  apt-get -y install libffi-dev
  git -C /opt/tools/ clone https://github.com/ThePorgs/impacket

  # See https://github.com/ThePorgs/impacket/blob/master/ChangeLog.md

  python3 -m pipx install /opt/tools/impacket/
  python3 -m pipx inject impacket chardet

  cp -v /root/sources/grc/conf.ntlmrelayx /usr/share/grc/conf.ntlmrelayx
  cp -v /root/sources/grc/conf.secretsdump /usr/share/grc/conf.secretsdump
  cp -v /root/sources/grc/conf.getgpppassword /usr/share/grc/conf.getgpppassword
  cp -v /root/sources/grc/conf.rbcd /usr/share/grc/conf.rbcd
  cp -v /root/sources/grc/conf.describeTicket /usr/share/grc/conf.describeTicket

  add-aliases impacket
  add-history impacket
  add-test-command "ntlmrelayx.py --help"
  add-test-command "secretsdump.py --help"
  add-test-command "Get-GPPPassword.py --help"
  add-test-command "getST.py --help && getST.py --help | grep 'u2u'"
  add-test-command "ticketer.py --help && ticketer.py --help | grep impersonate"
  add-test-command "ticketer.py --help && ticketer.py --help | grep hours"
  add-test-command "ticketer.py --help && ticketer.py --help | grep extra-pac"
  add-test-command "dacledit.py --help"
  add-test-command "describeTicket.py --help"
  add-to-list "impacket,https://github.com/ThePorgs/impacket,Set of tools for working with network protocols (ThePorgs version)."
}

function install_lsassy() {
  colorecho "Installing lsassy"
  python3 -m pipx install lsassy
  add-history lsassy
  add-test-command "lsassy --version"
  add-to-list "lsassy,https://github.com/Hackndo/lsassy,Windows secrets and passwords extraction tool."
}

function install_krbrelayx() {
  colorecho "Installing krbrelayx"
  python3 -m pip install dnspython ldap3
  #python -m pip install dnstool==1.15.0
  git -C /opt/tools/ clone https://github.com/dirkjanm/krbrelayx
  cd /opt/tools/krbrelayx/ || exit
  cp -v /root/sources/grc/conf.krbrelayx /usr/share/grc/conf.krbrelayx
  add-aliases krbrelayx
  add-history krbrelayx
  add-test-command "krbrelayx.py --help"
  add-test-command "addspn.py --help"
  add-test-command "addspn.py --help"
  add-test-command "printerbug.py --help"
  add-to-list "krbrelayx,https://github.com/dirkjanm/krbrelayx,a tool for performing Kerberos relay attacks"
}

function install_evilwinrm() {
  colorecho "Installing evil-winrm"
  gem install evil-winrm
  add-history evil-winrm
  add-test-command "evil-winrm --help"
  add-to-list "evilwinrm,https://github.com/Hackplayers/evil-winrm,Tool to connect to a remote Windows system with WinRM."
}

function install_enum4linux-ng() {
  colorecho "Installing enum4linux-ng"
  python3 -m pipx install git+https://github.com/cddmp/enum4linux-ng
  add-history enum4linux-ng
  add-test-command "enum4linux-ng --help"
  add-to-list "enum4linux-ng,https://github.com/cddmp/enum4linux-ng,Tool for enumerating information from Windows and Samba systems."
}

function install_smbclient() {
  colorecho "Installing smbclient"
  fapt smbclient
  add-history smbclient
  add-test-command "smbclient --help"
  add-to-list "smbclient,https://github.com/samba-team/samba,SMBclient is a command-line utility that allows you to access Windows shared resources"
}

function install_finduncommonshares() {
  colorecho "Installing FindUncommonShares"
  git -C /opt/tools/ clone https://github.com/p0dalirius/FindUncommonShares
  cd /opt/tools/FindUncommonShares/ || exit
  python3 -m pip install -r requirements.txt
  add-aliases finduncommonshares
  add-history finduncommonshares
  add-test-command "FindUncommonShares.py --help"
  add-to-list "finduncommonshares,https://github.com/p0dalirius/FindUncommonShares,Script that can help identify shares that are not commonly found on a Windows system."
}

function install_gmsadumper() {
  colorecho "Installing gMSADumper"
  git -C /opt/tools/ clone https://github.com/micahvandeusen/gMSADumper
  add-aliases gmsadumper
  add-history gmsadumper
  add-test-command "gMSADumper.py --help"
  add-to-list "gmsadumper,https://github.com/micahvandeusen/gMSADumper,A tool for extracting credentials and other information from a Microsoft Active Directory domain."
}

function install_rpcbind() {
  colorecho "Installing rpcbind"
  fapt rpcbind
  add-test-command "rpcbind"
  add-to-list "rpcbind,https://github.com/teg/rpcbind,RPCbind is a server that converts RPC program numbers into universal addresses."
}

function install_gpp-decrypt(){
  colorecho "Installing gpp-decrypt"
  python3 -m pip install pycrypto colorama
  git -C /opt/tools/ clone -v https://github.com/t0thkr1s/gpp-decrypt
  add-aliases gpp-decrypt
  add-test-command "gpp-decrypt.py -f /opt/tools/gpp-decrypt/groups.xml"
  add-to-list "gpp-decrypt,https://github.com/t0thkr1s/gpp-decrypt,A tool to decrypt Group Policy Preferences passwords"
}

function install_adidnsdump() {
  colorecho "Installing adidnsdump"
  python3 -m pipx install git+https://github.com/dirkjanm/adidnsdump
  add-history adidnsdump
  add-test-command "adidnsdump --help"
  add-to-list "adidnsdump,https://github.com/dirkjanm/adidnsdump,Active Directory Integrated DNS dump utility"
}

function install_petitpotam() {
  colorecho "Installing PetitPotam"
  git -C /opt/tools/ clone https://github.com/ly4k/PetitPotam
  mv /opt/tools/PetitPotam /opt/tools/PetitPotam_alt
  git -C /opt/tools/ clone https://github.com/topotam/PetitPotam
  add-aliases petitpotam
  add-history petitpotam
  add-test-command "petitpotam.py --help"
  add-to-list "petitpotam,https://github.com/topotam/PetitPotam,Windows machine account manipulation"
}

function install_dfscoerce() {
  colorecho "Installing DfsCoerce"
  git -C /opt/tools/ clone https://github.com/Wh04m1001/DFSCoerce.git
  add-aliases dfscoerce
  add-history dfscoerce
  add-test-command "dfscoerce.py --help"
  add-to-list "dfscoerce,https://github.com/Wh04m1001/dfscoerce,DFS-R target coercion tool"
}

function install_coercer() {
  colorecho "Installing Coercer"
  python3 -m pipx install git+https://github.com/p0dalirius/Coercer
  add-history coercer
  add-test-command "coercer --help"
  add-to-list "coercer,https://github.com/p0dalirius/coercer,DFS-R target coercion tool"
}

function install_donpapi() {
  colorecho "Installing DonPAPI"
  git -C /opt/tools/ clone https://github.com/login-securite/DonPAPI.git
  python3 -m pip install -r /opt/tools/DonPAPI/requirements.txt
  add-aliases donpapi
  add-history donpapi
  add-test-command "DonPAPI.py --help"
  add-to-list "donpapi,https://github.com/login-securite/DonPAPI,Python network and web application scanner"
}

function install_shadowcoerce() {
  colorecho "Installing ShadowCoerce PoC"
  git -C /opt/tools/ clone https://github.com/ShutdownRepo/ShadowCoerce
  add-aliases shadowcoerce
  add-history shadowcoerce
  add-test-command "shadowcoerce.py --help"
  add-to-list "shadowcoerce,https://github.com/ShutdownRepo/shadowcoerce,Utility for bypassing the Windows Defender antivirus by hiding a process within a legitimate process."
}

#####################
### => NETWORK
#####################
function install_nmap() {
  colorecho "Installing nmap"
  echo 'deb http://deb.debian.org/debian bullseye-backports main' > /etc/apt/sources.list.d/backports.list
  apt-get update
  fapt nmap/bullseye-backports
  add-aliases nmap
  add-history nmap
  add-test-command "nmap --version"
  add-to-list "nmap,https://nmap.org,The Network Mapper - a powerful network discovery and security auditing tool"
}

function install_masscan() {
  colorecho "Installing masscan"
  fapt masscan
  add-history masscan
  add-test-command "masscan --help; masscan --version | grep 'Masscan version'"
  add-to-list "masscan,https://github.com/robertdavidgraham/masscan,Masscan is an Internet-scale port scanner"
}

function install_proxychains() {
  colorecho "Installing proxychains"
  git -C /opt/tools/ clone https://github.com/rofl0r/proxychains-ng
  cd /opt/tools/proxychains-ng/ || exit
  ./configure --prefix=/usr --sysconfdir=/etc
  make
  make install
  # Add proxyresolv to PATH (needed with 'proxy_dns_old' config)
  ln -s /opt/tools/proxychains-ng/src/proxyresolv /usr/bin/proxyresolv
  make install-config
  cp -v /root/sources/proxychains/proxychains.conf /etc/proxychains.conf
  add-aliases proxychains
  add-test-command "proxychains4 echo test"
  add-test-command "proxyresolv"
  add-to-list "proxychains,https://github.com/rofl0r/proxychains,Proxy chains - redirect connections through proxy servers."
}

function install_wireshark() {
  colorecho "Installing Wireshark"
  DEBIAN_FRONTEND=noninteractive fapt wireshark
  #TODO add-test-command
  add-to-list "wireshark,https://github.com/wireshark/wireshark,Wireshark is a network protocol analyzer that lets you see what’s happening on your network at a microscopic level."
}

function install_tshark() {
  colorecho "Installing tshark"
  DEBIAN_FRONTEND=noninteractive fapt tshark
  add-test-command "tshark --version"
  add-to-list "tshark,https://github.com/wireshark/wireshark,TShark is a terminal version of Wireshark."
}

function install_traceroute() {
  colorecho "Installing traceroute"
  fapt traceroute
  add-to-list "traceroute,https://github.com/iputils/iputils,Traceroute is a command which can show you the path a packet of information takes from your computer to one you specify."
}

function install_iptables() {
  colorecho "Installing iptables"
  fapt iptables
  add-test-command "iptables --version"
  add-to-list "iptables,https://linux.die.net/man/8/iptables,Userspace command line tool for configuring kernel firewall"
}

function install_tcpdump() {
  colorecho "Installing tcpdump"
  fapt tcpdump
  add-test-command "tcpdump --version"
  add-to-list "tcpdump,https://github.com/the-tcpdump-group/tcpdump,a powerful command-line packet analyzer for Unix-like systems"
}

###############################
# INSTALL POC & SCANNER
###############################
function install_scanner_bluegate_cve(){
  colorecho "Installing SCANNER BlueGate"
  # Bluegate
  add-aliases "scanner_bluegate_cve20200610"
  add-history scanner_bluegate_cve20200610
}

function install_scanner_eternablue_cve(){
  colorecho "Installing SCANNER EternalBlue"
  # EternalBlue
  add-aliases "scanner_eternalblue_ms17010"
  add-history scanner_eternalblue_ms17010
}

function install_scanner_getgpp(){
  colorecho "Installing SCANNER GetGPP"
  # GETGPPP
  add-aliases "scanner_getgppcreds"
  add-history scanner_getgppcreds
}

function install_scanner_micra_cve(){
  colorecho "Installing SCANNER micRA"
  # MicRA
  add-aliases "scanner_micRA_cve20191040"
  add-history scanner_micRA_cve20191040
}

function install_scanner_netapi_cve(){
  colorecho "Installing SCANNER NetAPI"
  pip3 install python-nmap
  # NetAPI
  add-aliases "scanner_netapi_cve20084250"
  add-history scanner_netapi_cve20084250
}

function install_scanner_petitpotam(){
  colorecho "Installing SCANNER PetitPotam"
  # PetitPotam
  add-aliases "scanner_petitpotam"
  add-history scanner_petitpotam
}

function install_scanner_printnightmare_cve(){
  colorecho "Installing SCANNER PrintNightmare"
  # PrintNightmare
  add-aliases "scanner_printnightmare_cve20211675"
  add-history scanner_printnightmare_cve20211675
}

function install_scanner_rpcdump(){
  colorecho "Installing SCANNER RPCDump"
  # RPCDump
  add-aliases "scanner_rpcdump "
  add-history scanner_rpcdump
}

function install_scanner_samaacountname_cve(){
  colorecho "Installing SCANNER sAMAccountName"
  # sAMAccountName
  add-aliases "scanner_sAMAccountName_cve202142278"
  add-history scanner_sAMAccountName_cve202142278
}

function install_scanner_smbghost_cve(){
  colorecho "Installing SCANNER SMBGhost"
  # SMB Ghost
  add-aliases "scanner_smbghost_cve20200796"
  add-history scanner_smbghost_cve20200796
}

function install_scanner_smbbleed_cve(){
  colorecho "Installing SCANNER SMBBleed" 
  # SMB Bleed
  add-aliases "scanner_smbleed_cve20201206"
  add-history scanner_smbleed_cve20201206
}

function install_scanner_smbsigning(){
  colorecho "Installing SCANNER SMB signing" 
  # SMB Signing
  add-aliases "scanner_smbsigning"
  add-history scanner_smbsigning
}

function install_scanner_zerologon_cve(){
  colorecho "Installing SCANNER ZeroLogon"
  # Zero Logon
  add-aliases "scanner_zerologon_cve20201472"
  add-history scanner_zerologon_cve20201472
}

### POC
function install_poc_bluegate() {
  colorecho "Installing POC BlueGate"
  # Bluegate
  add-aliases "poc_bluegate_cve20200610"
  add-history poc_bluegate_cve20200610
}

function install_poc_eternalblue() {
  colorecho "Installing POC EternalBlue"
  # EternalBlue
  add-aliases "poc_eternalblue_ms17010"
  add-history poc_eternalblue_ms17010
}

function install_poc_netapi() {
  colorecho "Installing POC NetAPI"
  # NetAPI
  add-aliases "poc_netapi_cve20084250"
  add-history poc_netapi_cve20084250
}

function install_poc_petitpotam() {
  colorecho "Installing POC PetitPotam"
  # PetitPotam
  add-aliases "poc_petitpotam"
  add-history poc_petitpotam
}

function install_poc_printnightmare() {
  colorecho "Installing POC PrintNightmare"
  # PrintNightmare
  add-aliases "poc_printnightmare_cve20211675"
  add-history poc_printnightmare_cve20211675
}

function install_poc_samaacountname() {
  colorecho "Installing POC sAMAccountName"
  # sAMAccountName
  add-aliases "poc_sAMAccountName_cve202142278"
  add-history poc_sAMAccountName_cve202142278
}

function install_poc_smbghost() {
  colorecho "Installing POC SMB Ghost"
  # SMB Ghost
  add-aliases "poc_smbghost_cve20200796"
  add-history poc_smbghost_cve20200796
}

function install_poc_zerologon() {
  colorecho "Installing POC ZeroLogon" 
  # Zero Logon
  add-aliases "poc_zerologon_cve20201472"
  add-history poc_zerologon_cve20201472
}

function install_adminer() {
  colorecho "Installing AD Miner" 
  # AD Miner
  # pip3 install 'git+https://github.com/Mazars-Tech/AD_Miner.git'
  python3 -m pipx install 'git+https://github.com/Mazars-Tech/AD_Miner.git'
}



#####################
### => WORDLISTS
#####################
function install_seclists(){
  colorecho "Installing Seclists"
  git -C /usr/share/ clone https://github.com/danielmiessler/SecLists.git seclists
  cd /usr/share/seclists || exit
  rm -r LICENSE .git* CONTRIBUT* .bin
  add-test-command "[ -d '/usr/share/seclists/Discovery/' ]"
  add-to-list "seclists,https://github.com/danielmiessler/SecLists,A collection of multiple types of lists used during security assessments"
}

function install_crunch() {
  colorecho "Installing crunch"
  fapt crunch
  add-test-command "crunch --help"
  add-to-list "crunch,https://github.com/crunchsec/crunch,A wordlist generator where you can specify a standard character set or a character set you specify."
}

function install_rockyou(){
  colorecho "Installing rockyou"
  mkdir /usr/share/wordlists
  tar -xvf /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /usr/share/wordlists/
  ln -s /usr/share/seclists/ /usr/share/wordlists/seclists
  add-test-command "[ -f '/usr/share/wordlists/rockyou.txt' ]"
  add-to-list "rockyou,https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt,A password dictionary used by most hackers"
}

function install_cewl() {
  colorecho "Installing cewl"
  fapt cewl
  add-history cewl
  add-test-command "cewl --help"
  add-to-list "cewl,https://digi.ninja/projects/cewl.php,Generates custom wordlists by spidering a target's website and parsing the results"
}

function install_cupp() {
  colorecho "Installing cupp"
  fapt cupp
  add-test-command "cupp --help"
  add-to-list "cupp,https://github.com/Mebus/cupp,TODO"
}

function install_pass_station() {
  colorecho "Installing Pass Station"
  gem install pass-station
  add-history pass-station
  add-test-command "pass-station --help"
  add-to-list "pass,https://github.com/hashcat/hashcat,TODO"
}

function install_username-anarchy() {
  colorecho "Installing Username-Anarchy"
  git -C /opt/tools/ clone https://github.com/urbanadventurer/username-anarchy
  add-aliases username-anarchy
  add-test-command "username-anarchy --help"
  add-to-list "username-anarchy,https://github.com/urbanadventurer/username-anarchy,TODO"
}

function install_genusernames() {
  colorecho "Installing genusernames"
  mkdir -p /opt/tools/genusernames
  wget -O /opt/tools/genusernames/genusernames.function https://gitlab.com/-/snippets/2480505/raw/main/bash
  sed -i 's/genadname/genusernames/g' /opt/tools/genusernames/genusernames.function
  echo 'source /opt/tools/genusernames/genusernames.function' >> ~/.zshrc
  add-test-command "genusernames 'john doe'"
  add-to-list "genusernames,https://gitlab.com/-/snippets/2480505/raw/main/bash,GenUsername is a Python tool for generating a list of usernames based on a name or email address."
}

function install_hashcat() {
  colorecho "Installing hashcat"
  fapt hashcat
  add-history hashcat
  add-test-command "hashcat --help"
  add-to-list "hashcat,https://hashcat.net/hashcat,A tool for advanced password recovery"
}

function install_john() {
  colorecho "Installing john the ripper"
  #fapt qtbase5-dev
  git -C /opt/tools/ clone --depth 1 https://github.com/openwall/john
  cd /opt/tools/john/src || exit
  ./configure --disable-native-tests && make
  add-aliases john-the-ripper
  add-history john-the-ripper
  add-test-command "john --help"
  add-to-list "john,https://github.com/openwall/john,John the Ripper password cracker."
}

function install_fcrackzip() {
  colorecho "Installing fcrackzip"
  fapt fcrackzip
  add-history fcrackzip
  add-test-command fcrackzip --help
  add-to-list "fcrackzip,https://github.com/hyc/fcrackzip,Password cracker for zip archives."
}

function install_name-that-hash() {
  colorecho "Installing Name-That-Hash"
  python3 -m pipx install name-that-hash
  add-history name-that-hash
  add-test-command "nth --help"
  add-to-list "name-that-hash,https://github.com/HashPals/Name-That-Hash,Online tool for identifying hashes."
}


function install_pdfcrack() {
  colorecho "Installing pdfcrack"
  fapt pdfcrack
  add-test-command "pdfcrack --version"
  add-to-list "pdfcrack,https://github.com/robins/pdfcrack,A tool for cracking password-protected PDF files"
}

function install_bruteforce-luks() {
  colorecho "Installing bruteforce-luks"
  fapt bruteforce-luks
  add-test-command "bruteforce-luks -h |& grep 'Print progress info'"
  add-to-list "bruteforce-luks,https://github.com/glv2/bruteforce-luks,A tool to help recover encrypted LUKS2 containers"
}

##########################
## => MY BREAKADAY TOOLS
##########################
function install_breakaday() {
  add-aliases breakaday
  add-history breakaday
  # python-ldap
  sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev
  python3 -m pip install python-ldap
  python3 -m pip install GitPython
  python3 -m pip install neo4j
  python3 -m pip install chardet
}

######################################################
# GLOBAL FUNCTIONS FOR CREATING ENVIRONMENT
######################################################
##########################
## => ABOUT BREAKADAY
##########################
function creation_environment_breakaday() {
  ## Creation download environment
	cd /opt/tools/ || exit
	if [ ! -d "/opt/tools/PENTEST-TOOLKIT" ]; then
		mkdir "/opt/tools/PENTEST-TOOLKIT"
		mkdir "/opt/tools/PENTEST-TOOLKIT/DEFAULT_CREDS"
		mkdir "/opt/tools/PENTEST-TOOLKIT/POC"
		mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER"
		mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/NETWORK"
	fi
  if [ ! -d "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS" ]; then 
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/LocalWindows"
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS/DATABASE"
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS/DATABASE/Redis"
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS/MAILS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS/MAILS/smtp"
    mkdir "/opt/tools/PENTEST-TOOLKIT/POC/PROTOCOLS/OMI"
  fi
  if [ ! -d "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE" ]; then
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/BlueGate_CVE-2020-0610"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/GPP-Abuse_CVE-2014-1812"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/PrintNightmare_CVE-2021-34527"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/sAMAccountNameSpoofing_CVE-2021-42278"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/SMBGhost_CVE-2020-0796"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/WindowsNTLMTampering_CVE-2019-1040"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/CVE/ZeroLogon_CVE-2020-1472"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/LocalWindows"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/LocalWindows/CVE-2021-363934"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/EternalBlue_MS17-010"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/MS-VULNS/KerberosChecksum_MS14-068"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/VULNS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/VULNS/SMB-Pipes"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/VULNS/SMB-Pipes/PrinterBug"
  fi
  if [ ! -d "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS" ]; then
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/DOMAIN_NAME"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/DATABASE"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/DATABASE/Oracle"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/DATABASE/PostgreSQL"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/ERL-EPMD"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/ident"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/LPD"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/MDNS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/RMI"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/SMART-INSTALL"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/SMB"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/VNC"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/WEBSITES"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/WEBSITES/AEM"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/WEBSITES/all"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/WEBSITES/REPORTS"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/WEBSITES/squid"
    mkdir "/opt/tools/PENTEST-TOOLKIT/SCANNER/PROTOCOLS/X"
  fi

  ## General environment
	if [ ! -d "/workspace" ]; then mkdir "/workspace"; fi
	if [ ! -d "/workspace/PENTEST/" ]; then mkdir "/workspace/PENTEST"; fi
	if [ ! -d "/workspace/PENTEST/RESULTS/" ]; then mkdir "/workspace/PENTEST/RESULTS/"; fi
}



######################################################
# GLOBAL FUNCTIONS FOR DOWNLOADING PACKAGES PER TYPE
######################################################

##################################################
###############  AD         ######################
##################################################
## Package dedicated to the basic things the env needs
function package_base(){
  update || exit
  ## BASICS
  fapt software-properties-common
  add-apt-repository contrib
  add-apt-repository non-free
  apt-get update
  fapt man                        # Most important
  fapt git                        # Git client
  fapt lsb-release
  fapt zip
  fapt unzip
  fapt kmod
  fapt sudo                       # Sudo
  install_curl                    # HTTP handler
  fapt wget                       # Wget
  fapt gnupg2                     # gnugpg
  
  ## PROGRAMMING LANGUAGE
  install_php                     # Php language
  fapt python2                    # Python 2 language
  install_python3                 # Python 3 language
  fapt python2-dev                # Python 2 language (dev version)
  fapt python3-dev                # Python 3 language (dev version)
  fapt python3-venv
  install_rust_cargo
  ln -s /usr/bin/python2.7 /usr/bin/python  # fix shit
  install_python-pip              # Pip
  fapt python3-pip                # Pip
  python3 pip install --upgrade pip
  install_go                      # Golang language
  set_go_env
  fapt npm                        # Node Package Manager
  install_nvm
  install_yarn
  fapt gem                        # Install ruby packages
  fapt ruby ruby-dev

  ## TOOLS
  install_tmux                    # Tmux
  fapt zsh                        # Awesome shell
  install_ohmyzsh                 # Awesome shell
  fapt python-setuptools
  fapt python3-setuptools
  python3 -m pip install wheel
  python -m pip install wheel
  install_pipx
  install_fzf
  install_grc
  fapt automake                   # Automake
  fapt autoconf                   # Autoconf
  fapt make
  fapt gcc
  fapt g++

  ## COMMANDS BASICS
  fapt file                       # Detect type of file with magic number
  fapt lsof                       # Linux utility
  fapt less                       # Linux utility
  fapt x11-apps                   # Linux utility
  fapt net-tools                  # Linux utility
  fapt vim                        # Text editor
  install_ultimate_vimrc          # Make vim usable OOFB
  fapt nano                       # Text editor (not the best)
  fapt jq                         # jq is a lightweight and flexible command-line JSON processor
  fapt iputils-ping               # Ping binary
  fapt iproute2                   # Firewall rules
  install_openvpn                 # install OpenVPN
  fapt tidy
  fapt mlocate
  fapt libtool

  ## TOOLS NETWORK
  install_dnsutils                # DNS utilities like dig and nslookup
  fapt dos2unix                   # Convert encoded dos script
  DEBIAN_FRONTEND=noninteractive fapt macchanger  # Macchanger
  install_samba                   # Samba
  fapt ftp                        # FTP client
  install_ssh                     # SSH client
  fapt sshpass                    # SSHpass (wrapper for using SSH with password on the CLI)
  fapt telnet                     # Telnet client
  fapt nfs-common                 # NFS client
  install_snmp
  fapt ncat                       # Socket manager
  fapt netcat-traditional         # Socket manager
  fapt socat                      # Socket manager
  fapt putty                      # GUI-based SSH, Telnet and Rlogin client
  fapt screen                     # CLI-based PuTT-like

  ## OTHERS
  fapt p7zip-full                 # 7zip
  fapt p7zip-rar                  # 7zip rar module
  fapt-noexit rar                 # rar
  fapt unrar                      # unrar
  fapt xz-utils                   # xz (de)compression
  fapt xsltproc                   # apply XSLT stylesheets to XML documents (Nmap reports)
  fapt parallel
  fapt tree
  fapt nim
  fapt perl
  fapt openjdk-11-jre openjdk-11-jdk-headless
  fapt openjdk-17-jre openjdk-17-jdk-headless
  ln -s -v /usr/lib/jvm/java-11-openjdk-* /usr/lib/jvm/java-11-openjdk    # To avoid determining the correct path based on the architecture
  ln -s -v /usr/lib/jvm/java-17-openjdk-* /usr/lib/jvm/java-17-openjdk    # To avoid determining the correct path based on the architecture
  update-alternatives --set java /usr/lib/jvm/java-17-openjdk-*/bin/java  # Set the default openjdk version to 17
  install_chromium
  install_firefox
}

#######################
# => PACKAGES FOR AD
# Example usage:
# RUN /root/sources/install.sh package_base
# RUN /root/sources/install.sh package_base_breakaday
# RUN /root/sources/install.sh package_advanced_ad
# RUN /root/sources/install.sh package_exploit_ad
# RUN /root/sources/install.sh package_wordlists
# RUN /root/sources/install.sh package_cracking
# RUN /root/sources/install.sh package_network

#######################
## Package dedicated to the BREAKADAY tools
function package_base_breakaday() {
  set_go_env
  ## BASICS TOOLS
  # install_snmp                  # ALREADY DONE IN package_base
  install_dirb
  install_ffuf
  install_whatweb
  install_android-tools-adb
  fapt whois
  fapt dnsrecon
  fapt finger
  fapt ike-scan                     
  fapt rusers                   
  fapt subversion
  fapt libmemcached-tools
  # Base advanced
  install_responder               # LLMNR, NBT-NS and MDNS poisoner
  install_searchsploit            # Exploitdb local search engine
  install_metasploit              # Offensive framework
  install_nmap                    # Port scanner
  install_crackmapexec            # Network scanner
  install_impacket                # Network protocols scripts
  install_enum4linux-ng           # Active Directory enumeration tool, improved Python alternative to enum4linux
  install_smbclient               # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
  install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
  install_evilwinrm               # WinRM shell
}

# Package dedicated to internal Active Directory tools
function package_advanced_ad() {
  set_go_env
  install_responder               # LLMNR, NBT-NS and MDNS poisoner
  install_ldapdomaindump
  install_crackmapexec            # Network scanner
  install_bloodhound-py           # AD cartographer
  install_neo4j                   # Bloodhound dependency
  install_bloodhound
  # install_bloodhound_old_v3
  # install_bloodhound_old_v2
  install_impacket                # Network protocols scripts
  install_lsassy                  # Credentials extracter
  install_krbrelayx               # Kerberos unconstrained delegation abuse toolkit
  install_evilwinrm               # WinRM shell
  install_enum4linux-ng           # Hosts enumeration
  install_smbclient               # Small dynamic library that allows iOS apps to access SMB/CIFS file servers
  install_smbmap                  # Allows users to enumerate samba share drives across an entire domain
  install_rpcbind                 # RPC scanning
  install_gpp-decrypt             # Decrypt a given GPP encrypted string
  install_adidnsdump              # enumerate DNS records in Domain or Forest DNS zones
  install_bloodhound-import       # Python script to import BH data to a neo4j db
  install_bloodhound-quickwin     # Python script to find quickwins from BH data in a neo4j db
  install_ldapsearch              # LDAP enumeration utils
  install_ldapsearch-ad           # Python script to find quickwins from basic ldap enum
  install_petitpotam              # Python script to coerce auth through MS-EFSR abuse
  install_dfscoerce               # Python script to coerce auth through NetrDfsRemoveStdRoot and NetrDfsAddStdRoot abuse
  install_coercer                 # Python script to coerce auth through multiple methods
  install_donpapi
  install_shadowcoerce
  install_gmsadumper
  install_finduncommonshares
}

# Package dedicated to the installation of wordlists and tools like wl generators
function package_wordlists() {
  set_go_env
  install_crunch                  # Wordlist generator
  install_seclists                # Awesome wordlists
  install_rockyou                 # Basically installs rockyou (~same as Kali)
  install_cewl                    # Wordlist generator
  install_cupp                    # User password profiler
  install_pass_station            # Default credentials database
  install_username-anarchy        # Generate possible usernames based on heuristics
  install_genusernames
}
# Package dedicated to offline cracking/bruteforcing tools
function package_cracking() {
  set_go_env
  install_hashcat                 # Password cracker
  install_john                    # Password cracker
  install_fcrackzip               # Zip cracker
  install_pdfcrack                # PDF cracker
  install_bruteforce-luks         # Find the password of a LUKS encrypted volume
  install_name-that-hash          # Name-That-Hash, hash identifier tool
}

# Package dedicated to network pentest tools
function package_network() {
  export PATH=$PATH:/usr/local/go/bin
  install_proxychains             # Network tool
  install_wireshark               # Wireshark packet sniffer
  install_tshark                  # Tshark packet sniffer
  install_masscan                 # Port scanner
  install_nmap                    # Port scanner
  install_tcpdump                 # Capture TCP traffic
  install_iptables                # iptables for the win
  install_traceroute              # ping ping
}


################
# SCANNER & POC 
################
function package_tools_breakaday() {
  # BASIC
  install_breakaday

  # SCANNER
  install_scanner_bluegate_cve
  install_scanner_eternablue_cve
  install_scanner_getgpp
  install_scanner_micra_cve
  install_scanner_netapi_cve
  install_scanner_petitpotam
  install_scanner_printnightmare_cve
  install_scanner_rpcdump
  install_scanner_samaacountname_cve
  install_scanner_smbghost_cve
  install_scanner_smbbleed_cve
  install_scanner_smbsigning
  install_scanner_zerologon_cve

  # POC
  install_poc_bluegate
  install_poc_eternalblue
  install_poc_netapi
  install_poc_petitpotam
  install_poc_printnightmare
  install_poc_samaacountname
  install_poc_smbghost
  install_poc_zerologon

  # analysis AD data
  install_adminer
}

# Entry point for the installation
if [[ $EUID -ne 0 ]]; then
  criticalecho "You must be a root user"
else
  if declare -f "$1" > /dev/null
  then
    if [[ -f '/.dockerenv' ]]; then
      echo -e "${GREEN}"
      echo "This script is running in docker, as it should :)"
      echo "If you see things in red, don't panic, it's usually not errors, just badly handled colors"
      echo -e "${NOCOLOR}"
      "$@"
    else
      echo -e "${RED}"
      echo "[!] Careful : this script is supposed to be run inside a docker/VM, do not run this on your host unless you know what you are doing and have done backups. You are warned :)"
      echo -e "${NOCOLOR}"
      "$@"
    fi
  else
    echo "'$1' is not a known function name" >&2
    exit 1
  fi
fi
