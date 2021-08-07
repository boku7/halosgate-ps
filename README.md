# HalosGate Processlist Cobalt Strike BOF
Cobalt Strike Beacon Object File (BOF) that uses a custom HalosGate & HellsGate syscaller, written in assembly, to return a list of processes.

#### Getting that Processlist using direct systemcalls via HalosGate/HellsGate
![](/images/hgps1.png)
+ If there is no EDR hooks detected, the BOF will just default to using HellsGate

#### Verbose mode (-v) shows the memory addresses back to the CS console for debugging
![](/images/hgps-verbose.png)

### Compile with x64 MinGW (Only tested from MacOS compiling atm):
```bash
x86_64-w64-mingw32-gcc -c halosgate-ps.x64.c -o halosgate-ps.x64.o -masm=intel
```
### Run from Cobalt Strike Beacon Console
+ After compile import the halosgate-ps.cna script into Cobalt Strikes Script Manager
```bash
beacon> halosgate-ps
```

### To Do List
+ Free the memory allocated / fix memory leaks
+ Figure out a way to supress the "[+] received output:" messages in the Cobalt Strike console
+ Obfuscate the strings for that are used for resolving the addresses of the NTDLL symbols
  + Or use hashing
+ Build on this to make a series of BOFs that use this HalosGate/HellsGate syscaller to do direct systemcalls
+ Clean up the assembly functions

### Usage
```bash
beacon> halosgate-ps
[*] HalosGate Processlist BOF (Author: Bobby Cooke//SpiderLabs|@0xBoku|github.com/boku7)
[*]               Credits to: @SEKTOR7net @zodiacon @smelly__vx @am0nsec
[+] host called home, sent: 3232 bytes
   PID    PPID    Name
   ---    ----    ----
     0       0    (null)
     4       0    System
    92       4    Registry
   312       4    smss.exe
   436     424    csrss.exe
   512     424    wininit.exe
   532     504    csrss.exe
   624     504    winlogon.exe
   648     512    services.exe
   692     512    lsass.exe
   ...
```


### Credits / References
##### Reenz0h from @SEKTOR7net (Creator of the HalosGate technique )
  + This HalosGate project is based on the work of Reenz0h.
  + Most of the C techniques I use are from Reenz0h's awesome courses and blogs 
  + Best classes for malware development out there.
  + Creator of the halos gate technique. His work was the motivation for this work.
  + https://blog.sektor7.net/#!res/2021/halosgate.md 
  + https://institute.sektor7.net/
##### @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
  + Could not have made my implementation of HellsGate without them :)
  + Awesome work on this method, really enjoyed working through it myself. Thank you!
  + https://github.com/am0nsec/HellsGate 
  + Link to the Hell's Gate paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
##### Pavel Yosifovich (@zodiacon)
  + I learned how to correctly call NtQuerySystemInformation from Pavel's class on pentester academy. Full credits to Pavel for this. (BTW Pavel is an awesome teacher and I 100% recommend).
  + [Windows Process Injection for Red-Blue Teams - Module 2: NTQuerySystemInformation](https://www.pentesteracademy.com/video?id=1634)
##### OutFlank - Direct Syscalls in Beacon Object Files
  + Great blog about implementing x64 assembly into your CS BOF projects: https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/
##### Raphael Mudge - Beacon Object Files - Luser Demo
+ https://www.youtube.com/watch?v=gfYswA_Ronw
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
##### BOF Code References
###### anthemtotheego/InlineExecute-Assembly
+ https://github.com/anthemtotheego/InlineExecute-Assembly/blob/main/inlineExecuteAssembly/inlineExecute-Assembly.cna
###### ajpc500/BOFs
+ https://github.com/ajpc500/BOFs/
###### trustedsec/CS-Situational-Awareness-BOF
+ https://github.com/trustedsec/CS-Situational-Awareness-BOF
