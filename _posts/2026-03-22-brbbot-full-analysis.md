---
layout: post
title: "Brbbot: Full Malware Analysis & Reverse Engineering"
#image: /assets/images/brbbot/kali.PNG
date: 2026-03-22 12:00:00 +0200
categories: [Malware Analysis]
---

## Brbbot 
functions as a trojan or bot, it can also be used as a backdoor.<br>
*sample hash: `f9227a44ea25a7ee8148e2d0532b14bb640f6dc52cb5b22a9f4fa7fa037417fa`* 

### Quick triage
frisking strings was pretty useful, it gave me a pretty good idea about how the malware would behave.
![image](/assets/images/brbbot/s1.PNG)
![image](/assets/images/brbbot/s3.PNG)
a lot of network-related strings. these `encode` ,`sleep` ,`exit` ,`conf` ,`file` ,`exec`. we will find out later that they're the bot cmds. 
<br>
<br>
![image](/assets/images/brbbot/s2.PNG)
beside, there were encryption-related functions, which means we will have to deal with later.

using procmon, here we can see persistency-related behaviors(setting reg keys etc..), besides that, creating this `brbbotconfig.tmp`.
![image](/assets/images/brbbot/procmon.png)

and it's most likely encrypted, but we will come to decrypting it later.
![image](/assets/images/brbbot/tmpfile.PNG)

also, while searching resources, i found this, it may be related to the `brbbotconfig.tmp` artifact i found earlier, maybe it drops it and do its thing.
![image](/assets/images/brbbot/rcs.PNG)


### Traffic analysis & C2 communication
after a couple of minuets from running the sample for some traffic analysis, here i found that it's reaching for the c2 server `brb.3dtuts.by`, requiting `ads.php` and exfiltrating what it seems to be encrypted data (saved it for now, we'll get to deciphering it later).
![image](/assets/images/brbbot/nt1.png)
we can then set up an http server and pass this `ads.php` to the bot and see what'll happen (we will come to that later :D), since i was using FakeNet-ng, there were no any issues with the http request's response.


### Code analysis & Capabilities
since we could not tell what `brbbotconfig.tmp` exactly was, i found this's a good start.
i then managed to put a bp at `ReadFile` API so i can make sure that it's actually being read.
```cpp
BOOL ReadFile(
  [in]                HANDLE       hFile,
  [out]               LPVOID       lpBuffer,
  [in]                DWORD        nNumberOfBytesToRead,
  [out, optional]     LPDWORD      lpNumberOfBytesRead,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```
one of the parameters passed to `ReadFile` is a Handle to the resource that is being read. and it was `0x14c`
![image](/assets/images/brbbot/dbg_hndl.png)
![image](/assets/images/brbbot/dbg_hndl2.png)
i wanted to make sure that it was reading the file and it was a handle to the `brbbootconfig.tmp` file, so i managed to do that using both x32dbg and processhacker, and we're good.
![image](/assets/images/brbbot/dbg_hndl3.png)

frisking the import table, i found that it was using `CryptyDecrypt` function,which decrypts data that was previously encrypted by using the `CryptEncrypt` function. and after one step over, it was all decrypted.
![image](/assets/images/brbbot/dbg_decrypt.png)
`uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000`
we can assume that these are some bot cmds. the `encode=5b` value, was sort of interesting, seems like it's a key for encoding something.
* uri - the uri for the panel file on the c2 <br> exec, file, conf, exit - possible bot commands <br> encode - single byte key that will use us later on <br> sleep - sleeps a period of time

since we still have the encrypted exfiltrated data, using cyberchef, converted these hex to bytes, then xored it with the `0x5b` key. 
![image](/assets/images/brbbot/cyberchef.png)
looks interesting, here it's doing what it called process enumeration (that'll be covered at code analysis section), it's quite obvious why.
my be to see if there any exploitable apps, useful apps that helps with thr post-exploitation etc..
<br>

now its ghidra time, usually when analyzing malware samples such this, i search **Symbolic References**, and i can tell, it's pretty useful. <br>
![image](/assets/images/brbbot/ghidra.png)

i first found a reference to Reg Keys Apis such `RegOpenKeyExA`, `RegSetValueExA`. i knew this have to do with *persistency*, so i navigated to them.
and as was expected, here it opens `\Microsoft\Windows\CurrentVersion\Run` key, and passes `brbbot`
![image](/assets/images/brbbot/ghidra_1.png) <br>

also, i found many references to Resource-related Apis such as `FindRecource`, so i went and navigated through them.
 ![image](/assets/images/brbbot/ghidra_2.png)
earlier we found that `CONFIG` Resource, we assumed that it has something to do with `brbbotconfig.tmp`, and this confirms that. it loads that waht it called `CONFIG` resource, and drops it to the disk under the name `brbbotconfig` that we decrypted later.

we noticed later at the traffic analysis section that it's exfiltrating our system's processes (process enumeration), it was doing that by getting a handle to `ntdll.dll` using `GetModuleHandleA`.
```cpp
HMODULE GetModuleHandleA(
  [in, optional] LPCSTR lpModuleName
);
``` 
it takes the name of a loaded module as a parameter. in our case it was `ZwQuerySystemInformation`.
![image](/assets/images/brbbot/ghidra_3.png)

this technique called **Dynamic API Resolution**, 
where instead of calling `ZwQuerySystemInformation(...)` directly, the malware does this 
```cpp
hModule = GetModuleHandleA("ntdll.dll");
func = GetProcAddress(hModule, "ZwQuerySystemInformation");
func(...);
```
![image](/assets/images/brbbot/DAR.png)
_Dynamic API Resolution_

after a couple of minutes of analyzing, we can see here that it's decrypting `brbbotconfig.tmp` using `YnJiYm90` key. after that, it extracts the keys using `FUN_0100236a` function.
![image](/assets/images/brbbot/ghidra_4.png)

### Brbbot command and control
in order to make it execute our `ads.php`, i managed to set up an apache server and i then created an `ads.php` that contains `cexe c:\windows\notepad.exe`.
![image](/assets/images/brbbot/kali1.png)
![image](/assets/images/brbbot/kali.png)
also i made sure that my kali machine was set as the DNS server.
the ip addresses here are different from before, thats because i had to make a vm virtual network, in order to set all of this up.

![image](/assets/images/brbbot/kali3.png)
indeed! now we control the malware. what happened that, instead of reaching for the c2 server and its `ads.php`, it been redirected to our kali machine, reached for our `ads.php` file and executed the cmd that we did set :DD. and there we go it executed the command and opened the `notedpad.exe` as a child process successfully.
