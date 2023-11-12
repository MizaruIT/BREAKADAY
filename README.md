## 📗 Table of contents
* [📖 About the project](#about-the-project)
* [🛠 Installation](#installation)
* [💻 Getting started](#getting-started)
	* [Usage](#usage)
	* [Structure of the project](#structure-project)
	* [Use example(s)](#use-examples)
* [🔭 Roadmap](#roadmap)
* [👥 Contact](#contact)
* [🤝 Contributing](#contributing)
* [🙏 credits](#credits)

**[ATTENTION]** The script provided is for educational and informational purposes only, I am not responsible of any actions that you could take with it.

## 📖 About the project <a name="about-the-project"/>
During a penetration test on an Active Directory (AD) infrastructure, it often hapens to find some unpatched workstations, servers, etc. To automate the searching process for these vulnerable versions, the script has been created. The first version was scripted in Bash and is available on:  https://github.com/MizaruIT/BREAKADAY_BASH.

In addition of the searching part, the script was made to find new ways of compromission. For this, the database Neo4j (and BloodHound) is used to create the paths of compromission from the vulnerable computers. In brief, for each computer vulnerable, a new value "isVulnerableToX" is set. It can be used with cypher queries.

## 🛠 Installation <a name="installation"/>
**NEW WAY - Via Docker : AIO**

All the explanations of the Docker installation (creation of the image, run, and launch are described into DOCKER/HowToDocker.txt). You just need to replace the term with a "$".

!!! HOWEVER THE SCRIPT "breakaday.py" IS ONLY EXECUTABLE THROUGH THE DIRECTORY CONTAINING THE FOLDER: SCAN, SCAN_AD & POC.  A CONTRARIO FROM THE BASH VERSION: https://github.com/MizaruIT/BREAKADAY_BASH.

**With detailed explanations**
```sh
## Build the image (from the root folder of the project BREAKADAY_BASH)
docker build -f DOCKER/breakaday.all.dockerfile . -t breakaday_all

## Create the containeur : choose the shared folder from your host, then you can work with it.
docker run -it -v $/$SHARED_FOLDER_FROM_HOST/:/workspace --name $DOCKER_CONTAINER_NAME $DOCKER_IMAGE_NAME (here = breakaday_all)

## Once, you want to relaunch it, just find the container with the name specified previously and relaunch it
# To find the list of containers (running or exited)
docker container ls -a
breakaday_all     latest    4c471cffda24   15 hours ago        11.5GB

# Start and execute it (as an example, there the ID would be = 4c471cffda24)
docker start $ID 
docker exec -it $ID zsh
```

**All in one - Create the container (with the name = persistent_breakaday_all) with the shared folder into your current directory**
```sh
docker build -f DOCKER/breakaday.all.dockerfile . -t breakaday_all
docker run -it -v $(pwd):/workspace --name persistent_breakaday_all breakaday_all

# And then to use the script, you must have POC/SCANNER_AD/SCANNER folders into the same directory than the script 
# Go into the directory created for
cd /opt/tools/my_scripts/BREAKADAY

# Launch it

```

Once you are into the container, you get access to the scripts and the scanners/PoC tools
```sh
# Scanner Tools
[May 31, 2023 - 20:19:31 (UTC)] 4a7cd65bdc93 /opt/tools/my_scripts/BREAKADAY # scanner_
scanner_bluegate_cve20200610         scanner_micRA_cve20191040            scanner_printnightmare_cve20211675   scanner_smbleed_cve20201206                
scanner_eternalblue_ms17010          scanner_netapi_cve20084250           scanner_sAMAccountName_cve202142278  scanner_smbsigning                
scanner_getgppcreds                  scanner_petitpotam                   scanner_smbghost_cve20200796         scanner_zerologon_cve20201472

# PoC Tools
[May 31, 2023 - 20:21:10 (UTC)] 4a7cd65bdc93 /opt/tools/my_scripts/BREAKADAY # poc_
poc_bluegate_cve20200610         poc_netapi_cve20084250           poc_printnightmare_cve20211675   poc_smbghost_cve20200796         
poc_eternalblue_ms17010          poc_petitpotam                   poc_sAMAccountName_cve202142278  poc_zerologon_cve20201472

# Breakaday script
[May 31, 2023 - 20:21:47 (UTC)] 4a7cd65bdc93 /opt/tools/my_scripts/BREAKADAY # breakaday 
 ______   ______ _______ _______ _     _ _______ ______  _______ __   __
 |_____] |_____/ |______ |_____| |____/  |_____| |     \ |_____|   \_/  
 |_____] |    \_ |______ |     | |    \_ |     | |_____/ |     |    |   
                                                                        
by 
@MizaruIT on Twitter: wwW.twitter.com/MizaruIT
@MizaruIT on GitHub: www.github.com/MizaruIT

=> MAIN MENU
1) Option 1: Scanning network
2) Option 2: Searching for known vulnerabilities
3) Option 3: Exploiting vulnerabilities
4) Option 4: Setting and requesting BloodHound
5) Option 5: Adding or removing informations (accounts, etc.)
6) Option 6: Show list of attacks and their details (description, exploitation steps, mitigations, etc.)
7) Option 7: QUIT

```

**I) Command per command**
1) Clone the repository
```sh
git clone https://github.com/MizaruIT/BREAKADAY.git;
cd BREAKADAY;
```
2) Install the required dependencies
```sh
bash requirements_linux.txt;
pip3 install -r requirements.txt;
```

3) **(Optional)** To use the script from everywhere, just run the following command
```sh
sudo ln -sf $(pwd)/breakaday.py breakaday
```
**II) All commands in one (copy/paste)**
```sh
git clone https://github.com/MizaruIT/BREAKADAY.git;
cd BREAKADAY;
bash linux_requirements.txt;
pip3 install -r requirements.txt;
sudo ln -sf $(pwd)/breakaday.py breakaday
```

## 💻 Getting started <a name="getting-started"/>
The script is interactive, once executed, it will be shown with a menu and you only need to select the actions to realize.
### Usage <a name="usage"/>
1) Launch the script 
```sh 
python3 breakaday.py
```
2) Then, you will be prompted with a menu with different options. Select the actions to realize among the following:
```sh
[1] Option 1: Scanning network
[2] Option 2: Searching for known vulnerabilities
[3] Option 3: Exploiting known vulnerabilities
[4] Option 4: Setting and requesting BloodHound
[5] Option 5: Adding or removing information (accounts, etc.)
[6] Option 6: Show list of attacks and their details (description, exploitation steps, mitigations, etc.)
[7] Option 7: Quit
```
<details>
	<summary>Option 1: Scanning network</summary>
	<ol>
	<p>You will have to enter the network range to scan (IP/subnet). If already scanned, you will have the choice to re-scan among the scanned ranges or to scan a new.</p>  
	<p>Once the range is written, it will be scanned for specific ports and infos about the domain (domain name, DCs IP and hostnames, etc.).</p>
	<p>:information_source: If you already have this information, you can import them into the files in <b>known-data/network</b> folder (to see where it is located: <a href="#structure-project">Structure of the project</a>)</p>
	</ol>
</details>

<details>
	<summary>Option 2: Searching for vulnerabilities on the network</summary>
	<ol>
	You will have to choose among the 4 following cases (<b>depending on the information in your possession</b>):
<pre>[1] Option 1: Scanning without any accounts
[2] Option 2: Scanning with a domain account (with low privs)
[3] Option 3: Scanning with a local account (with low privs)
[4] Option 4: Scanning with a local account (with high privs)
[5] Option 5: Return to the main menu</pre>
Depending on the selected case, you will have many vulnerabilities to scan for:
		<details>
		<summary>Option 1: Scanning without any accounts</summary>
		For this option, you will be prompted to choose a domain to use for the scan. Then, you will have to choose among the following vulnerabilities:
		<pre>[1] Option 01: Searching for IP vulnerable to SMBGhost attack
[2] Option 02: Searching for IP vulnerable to SMBleed attack
[3] Option 03: Searching for IP vulnerable to MS17-010 attack
[4] Option 04: Searching for IP vulnerable to MS08-067 attack
[5] Option 05: Searching for IP vulnerable to PetitPotam with null session attack
[6] Option 06: Searching for IP vulnerable to SMB Signing defect
[7] Option 07: Searching for IP vulnerable to PrinterBug (or SpoolSample) attack
[8] Option 08: Searching for IP vulnerable to MS14-068 (Kerberos Checksum attack) attack
[9] Option 09: Searching for IP vulnerable to ZeroLogon attack
[10] Option 10: Searching for IP vulnerable to GPP abuse attack
[11] Option 11: Searching for IP vulnerable to BlueGate attack
[12] Option 12: Return to the main menu</pre>
		</details>
		<details>
		<summary>Option 2: Scanning with a domain account (with low privs)</summary>
		For this option, you will be prompted to choose a domain and a domain user (among those written into the directory: <b>known-data/accounts</b> and the files: <b>domain-infos_list.txt, dom-users_list.txt</b>) to use for the scan. Then, you will have to choose among the following vulnerabilities:
	<pre>[1] Option 01: Searching for IP vulnerable to Eternal Blue (or MS17-010) attack
[2] Option 02: Searching for IP vulnerable to PrintNightmare attack
[3] Option 03: Searching for IP vulnerable to MIC Remove attack
[4] Option 04: Searching for IP vulnerable to PetitPotam attack
[5] Option 05: Searching for IP vulnerable to sAMAccountName spoofing attack
[6] Option 06: Searching for IP vulnerable to GPP Abuse with account attack
[7] Option 07: Searching for IP vulnerable to SMB Pipes attacks
[8] Option 08: Return to the main menu</pre>
		</details>
		<details>
		<summary>Option 3: Scanning with a local account (with low privs)</summary>
		This option is not implemented for now, but among the vulnerabilities that will be surely implemented:
			- SeriousSam (HiveNightmare)
		</details>
		<details>
		<summary>Option 4: Scanning with a local account (with high privs)</summary>
		This option is not implemented for now, but among the vulnerabilities that will be surely implemented:
		- SeriousSam (HiveNightmare)
		</details>
		If you have any others vulnerabilities to add, open an issue, I will then add it/them to the project.
	</ol>
</details>
<details>
	<summary>Option 3: Exploit the found vulnerabilities</summary>
You will have to choose among the 4 following cases (<b>depending on the information in your possession</b>):
<pre>[1] Option 1: Exploiting without any accounts
[2] Option 2: Exploiting with a domain account (with low privs)
[3] Option 3: Exploiting with a local account (with low privs)
[4] Option 4: Exploiting with a local account (with high privs)
[5] Option 5: Return to the main menu</pre>
Depending on the selected case, you will have many vulnerabilities to scan for:
		<details>
		<summary>Option 1: Exploiting without any accounts</summary>
		For this option, you will be prompted to choose a domain to use for the exploit. Then, you will have to choose among the following vulnerabilities (the [!] shows the risky level of the exploit (to break the AD)):
		<pre>[1] Option 01: Exploiting IP vulnerable to SMBGhost attack...                       [!!]
[2] Option 02: Exploiting IP vulnerable to SMBleed attack...                        [!!]
[3] Option 03: Exploiting IP vulnerable to MS17-010 attack...                       [!!]
[4] Option 04: Exploiting IP vulnerable to MS08-067...                              [!!!]
[5] Option 05: Exploiting IP vulnerable to PetitPotam with null session attack...   []
[6] Option 06: Exploiting IP vulnerable to SMB Signing attack...                    []
[7] Option 07: Exploiting IP vulnerable to PrinterBug (or SpoolSample) attack...    []
[8] Option 08: Exploiting IP vulnerable to MS14-068 (Kerberos Checksum) attack...   []
[9] Option 09: Exploiting IP vulnerable to ZeroLogon attack...                      [!!!]
[10] Option 10: Exploiting IP vulnerable to GPP abuse attack...                     []
[11] Option 11: Exploiting IP vulnerable to BlueGate attack...                      [!!!]
[12] Option 12: Return to the main menu</pre>
		</details>
		<details>
		<summary>Option 2: Exploiting with a domain account (with low privs)</summary>
		For this option, you will be prompted to choose a domain and a domain user (among those written into the directory: <b>known-data/accounts</b> and the files: <b>domain-infos_list.txt, dom-users_list.txt</b>) to use for the exploit. Then, you will have to choose among the following vulnerabilities:
	<pre>[1] Option 01: Exploiting IP vulnerable to Eternal Blue (or MS17-010) attack    [!!]
[2] Option 02: Exploiting IP vulnerable to PrintNightmare attack                [!]
[3] Option 03: Exploiting IP vulnerable to MIC Remove attack                    []
[4] Option 04: Exploiting IP vulnerable to PetitPotam attack                    []
[5] Option 05: Exploiting IP vulnerable to sAMAccountName spoofing attack       [!]
[6] Option 06: Exploiting IP vulnerable to GPP Abuse with account attack        []
[7] Option 07: Exploiting IP vulnerable to SMB Pipes attacks                    []
[8] Option 08: Return to the main menu</pre>
		</details>
		<details>
		<summary>Option 3: Scanning with a local account (with low privs)</summary>
		This option is not implemented for now, but among the vulnerabilities that will be surely implemented:
			- SeriousSam (HiveNightmare)
		</details>
		<details>
		<summary>Option 4: Scanning with a local account (with high privs)</summary>
		This option is not implemented for now, but among the vulnerabilities that will be surely implemented:
		- SeriousSam (HiveNightmare)
		</details>
		If you have any others vulnerabilities to add, open an issue, I will then add it/them to the project.
	</ol>
</details>

<details>
	<summary>Option 4: Setting and requesting BloodHound</summary>
	<ol>
		<p>For this option, <b>you must have your Neo4j database running</b>. Once it is running, you will be asked for your Neo4j username, password and port.</p>
		<p>The 2nd step to import correctly the data into Neo4j is that: <b>you must have a valid domain user account</b>. It will be asked, and then, the data is imported and you can request your database to search for compromissions' paths.</p>		
		<p>Different cypher-queries will be used to search for compromissions, some of them:</p>
		- NOT DONE (FOR NOW)
	</ol>
</details>

<details>
	<summary>Option 5: Adding or removing informations about the pentest (accounts, etc.)</summary>
	<ol>
	For this option, you will be prompted two options: adding or removing infos. Choose among one of them:
		<pre>[1] Option 1: Add informations
[2] Option 2: Remove informations
[3] Option 3: Return to the main menu</pre>
		The type of information (available into the directory <b>known-data/accounts</b>) are:
		<div>▪ <b>Accounts</b>: Format = username,password,NTLM_hash (<b>example</b>: user,password,aa3befefefef:FEFEFEF)</div>
		<div>▪ <b>Domain controllers</b>: Format = domain_controller_hostname,domain_controller_ip (<b>example</b>: dc01-enterprise,192.168.0.1)</div>
		<div>▪ <b>Domains</b>: Format = fqdn,domain,tld (<b>example</b>: enterprise.local,enterprise,local)</div>
Depending on the selected case, you will be able to add or remove infos (of the <b>known-data/accounts</b> folder). 
		<details>
		<summary>Option 1: Add informations</summary>
		For this option, you will have to choose the information type to add (local user, domain user, DC, etc.): 
		<pre>[[1] Option 1: ADD a local user
[2] Option 2: ADD a local administrator user
[3] Option 3: ADD a domain user
[4] Option 4: ADD domain infos
[5] Option 5: ADD a Domain Controller (DC)
[6] Option 6: Return to the previous menu
[7] Option 7: Return to the main menu</pre>
		</details>
		<details>
		<summary>Option 2: Remove informations</summary>
		For this option, you will have to choose the information type to remove (local user, domain user, DC, etc.): 
		<pre>[1] Option 1: DELETE a local user
[2] Option 2: DELETE a local administrator user
[3] Option 3: DELETE a domain user
[4] Option 4: DELETE domain infos
[5] Option 5: DELETE a Domain Controller (DC)
[6] Option 6: Return to the previous menu
[7] Option 7: Return to the main menu</pre>
		</details>
	</ol>
</details>


<details>
	<summary>Option 6: List all the attacks and their details (description, exploitation steps, mitigations, etc.)</summary>
	<ol>
	For this option, you will be prompted all the available attacks of the tool. You just need to select one of them to get all the details about it (description, exploit steps, mitigations, links):
	<pre>[1] Option 01: Show details about SMBGhost attack
[2] Option 02: Show details about SMBleed attack
[3] Option 03: Show details about Eternal Blue (or MS17-010) attack
[4] Option 04: Show details about Netapi (or MS08-067) attack
[5] Option 05: Show details about PetitPotam
[6] Option 06: Show details about SMB Signing attack
[7] Option 07: Show details about PrinterBug (or SpoolSample) attack
[8] Option 08: Show details about MS14-068 (Kerberos Checksum attack) attack
[9] Option 09: Show details about ZeroLogon attack
[10] Option 10: Show details about GPP abuse attack
[11] Option 11: Show details about BlueGate attack
[12] Option 12: Show details about PrintNightmare attack
[13] Option 13: Show details about MIC Remove (or Drop The Mic) attack
[14] Option 14: Show details about sAMAccountName spoofing attack
[15] Option 15: Show details about SMB Pipes attacks
[16] Option 16: Return to the main menu
</pre>
	</ol>
</details>

### Structure of the project <a name="structure-project"/>
The project has the following structure once it is launched for the first time (the folder known-data is created at the launch execution).

[!] The scanner <b>must be run from the root folder</b> (or the folders SCANNER, SCANNER_AD must be its subfolders) due to the existing symlinks used.

    ├── POC/	 		# The scripts for PoC of known vulnerabilities
    ├── SCANNER/ 		# The scanners used to check if an IP, DC, etc. is vulnerable to a specific attack
    ├── SCANNER_AD/		# The scanners used to query the Active Directory (via nmap, LDAP, etc.)
    ├── known-data/		# It contains folders filled with data obtained during the reconnaissance and exploitation phases. 
    │   ├── accounts/	# Data about the known accounts + domain infos (local accounts, domain accounts, domain controllers IP/name, etc.)
    │   ├── exploits/	# Data about the exploits (such as shellcode, etc.)
    │   ├── network/	# Data about the network (retrieved during the scanning/reconnaissance phase) such as RPC, SMB, RDG opened ports, etc.
    │   └── vulns/		# Data about the vulnerabilities exploited during the "reconnaissance" phase with exploits (CVE, MS, etc.)
    └── breakaday.py	# The All-In-One tool used to enumerate, scan, and ease the Active Directory compromission
    └── requirements.txt			# The python dependencies required to make it works.
    └── ubuntu_requirements.txt		# The Linux dependencies required to make it works (especially the exploitation part)

### Use example(s) <a name="use-examples"/>
The recommended way to use the script is the following:

**1) Launch it**
```sh
python3 breakaday.py
```

**2) Scan the network by choosing: "Option 1: Scanning the network"**

You will be asked for the range (network/subnet), enter it and then the results are now stored into **known-data/network**.

**3) (Optional) Depending on the information in your possession:**

- Do you have any accounts? 
- Do you have any DCs (IP, hostname) infos not already know?

If yes, select: **"Option 5: Add infos"** and add the account(s) and DCs to the known data (it will be added into **known-data/accounts**).

If no, pass to the **step 4**.

**4) Search for known vulnerabilities (CVE, MS, etc.) by choosing: "Option 2: Searching for vulnerabilities"**

You will be asked to choose the scenario that you want to try (ex: without account, with a domain account, etc. thus it refers to the **step 3**). 

Once you selected it, you will have to choose among the potential vulnerabilities. While there is a vulnerability that you want to try, select it and wait, then the results are now stored into **known-data/vulns**.

**5) Launch your Neo4j database and select "Option 4: Setting and requesting BloodHound"**

It will ask you your neo4j username, password and port used by the database, enter them. Then, to import the data retrieved from the **step 4**, you **must have a valid domain account**. If you don't already added any domain accounts into the file, go back to the **step 3** if you have one, else, you should go to the **step 6** and try to compromise the Active Directory a bit more (at least having a domain account) before doing the **step 5**. 

**6) Try to exploit the potential vulnerabilities**


## 🔭 ROADMAP <a name="roadmap"/>
- [x] Add a function to scan the network (RPC, microsoft DS, RDG ports and domain + domain controllers infos)
- [x] Add a function to search for vulnerable IPs, DCs, etc.
	- [ ] Improve the function to retrieve the DC hostname
	- [ ] Create a .ps1 script for local attacks? (idk)
- [x] Create the same script but in Bash programming langage (url:[URL](https://github.com/MizaruIT/BREAKADAY_BASH)) 
- [x] Add a function to set data in BloodHound
	- [ ] Create shortestPaths from owned (IP vulnerable to attacks) to DA, DCs, etc.
- [x] Add a function for adding, removing infos about the pentest (such as accounts, domain infos, DC infos, etc.)
- [x] Add a function to get information about the different attacks (description, exploit steps, mitigations, links)
- [x] Add a function to exploit vulnerable IP, DCs, etc. depending on the result of the searching function
 	- [ ] Add exploits for local accounts
 	- [ ] Implement others exploits
 	- [ ] Verify that the exploitations for each implemented vulnerabilities are working (especially the shellcode generation + reverse shell)


## 👥 Contact <a name="contact"/>
- Twitter: @MizaruIT (https://twitter.com/MizaruIT)
- GitHub: @MizaruIT (https://github.com/MizaruIT)
- Project Link: https://github.com/MizaruIT/BREAKADAY

## 🤝 Contributing <a name="contributing"/>
Contributions, issues, and feature requests are welcome!

Feel free to send me messages to add new features (such as new vulnerabilities, new scan, etc.)

## 🙏 Credits <a name="credits"/>
The project uses different scripts from various sources (to do: quote the sources of some scripts).

Some links are listed into SCANNER/00.LIST_SCANNER_GITHUB.txt and POC/00.LIST_POCs_GITHUB.txt
