# HalosGate Processlist Cobalt Strike BOF
Cobalt Strike Beacon Object File (BOF) that uses a custom HalosGate & HellsGate syscaller, written in assembly, to return a list of processes.

### Credits / References
+ Reenz0h from @SEKTOR7net (Creator of the HalosGate technique )
  + This HalosGate project is based on the work of Reenz0h.
  + Most of the C techniques I use are from Reenz0h's awesome courses and blogs 
  + Best classes for malware development out there.
  + Creator of the halos gate technique. His work was the motivation for this work.
  + https://blog.sektor7.net/#!res/2021/halosgate.md 
  + https://institute.sektor7.net/
+ @smelly__vx & @am0nsec ( Creators/Publishers of the Hells Gate technique )
  + Could not have made my implementation of HellsGate without them :)
  + Awesome work on this method, really enjoyed working through it myself. Thank you!
  + https://github.com/am0nsec/HellsGate 
  + Link to the Hell's Gate paper: https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf
+ Pavel Yosifovich (@zodiacon)
  + I learned how to correctly call NtQuerySystemInformation from Pavel's class on pentester academy. Full credits to Pavel for this. (BTW Pavel is an awesome teacher and I 100% recommend).
  + [Windows Process Injection for Red-Blue Teams - Module 2: NTQuerySystemInformation](https://www.pentesteracademy.com/video?id=1634)
+ OutFlank - Direct Syscalls in Beacon Object Files
+ Great blog about implementing x64 assembly into your CS BOF projects: https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/
