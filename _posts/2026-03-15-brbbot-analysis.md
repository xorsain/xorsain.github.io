---
layout: post
title: "Brbbot: Full Malware analysis"
date: 2026-03-15 12:00:00 +0200
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
we can then set up an http server and pass this `ads.php` to the bot and see what'll happen, since i was using FakeNet-ng, there were no any issues with the http request's response.
in order to make it execute our `ads.php`, i managed to set up an apache server and i then created an `ads.php` that contains `cexe c:\windows\notepad.exe`.
![image](/assets/images/brbbot/kali1.png)
![image](/assets/images/brbbot/kali.png)
also i made sure that my kali machine was set as the DNS server.
the ip addresses here are different from before, thats because i had to make a vm virtual network, in order to set all of this up.

![image](/assets/images/brbbot/kali3.png)
indeed! what happened that, instead of reaching for the c2 server and its `ads.php`, it been redirected to our kali machine, reached for our `ads.php` file and executed the cmd that we did set :DD. and there we go it executed the command and opened the `notedpad.exe` as a child process successfully.


### Code analysis & Capabilities
since we could not tell exactly what `brbbotconfig.tmp` exactly was, i found this a good start.
i then managed to put a bp at `ReadFile` API so i can make sure that it's actually being read.
```c
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
![image](/assets/images/brbbot/dbg_hndl3.png)
<br>i wanted to make sure that it was reading the file and it was a handle to the `brbbootconfig.tmp` file, so i managed to do that using both x32dbg and processhacker, and we're good.

frisking the import table, i found that it was using `CryptyDecrypt` function,which decrypts data that was previously encrypted by using the `CryptEncrypt` function. and after one step over, it was all decrypted.
![image](/assets/images/brbbot/dbg_decrypt.png)
`uri=ads.php;exec=cexe;file=elif;conf=fnoc;exit=tixe;encode=5b;sleep=30000`
we can assume that these are some bot cmds. the `encode=5b` value, was sort of interesting, seems like it's a key for encoding something, since we still have the encrypted exfiltrated data from the traffic analysis section, now we have a key and encrypted data. by doing some static code analysis, i think we will figure what encryption algorithm was used.  

now, it's time for some decrypting. using cyberchef, converted these hex to bytes, then xored it with the `0x5b` key. 
![image](/assets/images/brbbot/cyberchef.png)
looks interesting, here it's collecting all the processes, it's quite obvious why.
this is a common bots behavior, to see if there any exploitable apps, useful apps that helps with post-exploitation etc..
