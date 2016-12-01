# malcheck
Portable utility to check if a machine has been infected by Shamoon2

This utility uses a set of the Indicators of Compromise for the identified Shamoon variant released by FireEye [1]. As a GCC/Gulf based cyber security start-up, Comae recommends GCC private and public organizations to check their Windows environment using open-source utility malcheck.

This week, several security companies issued warnings regarding a new variation of Shamoon (W32.Disttrack), being found mid November 2016.
This utility available in *bin/malcheck.exe* contains a portable utility for simple check that your security team can use for quick assessment.


```
  MalCheck v0.1 - Simple portable utility to search for Shamoon2 artifacts
  Copyright (C) 2016, Matthieu Suiche <http://www.msuiche.net>
  Copyright (C) 2016, Comae Technologies FZE <http://www.comae.io>
      More information: support@comae.io

[+] No signs of Shamoon2 have been found.
```

## TODO
- [ ] Parse JSON files as input argument instead of hardcoding quick signatures.

## References
- [1] *FireEye* https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html
- [2] *Symantec* https://www.symantec.com/connect/blogs/shamoon-back-dead-and-destructive-ever
- [3] *McAfee* https://securingtomorrow.mcafee.com/mcafee-labs/shamoon-rebooted/
- [4] *CrowdStrike* https://www.crowdstrike.com/blog/shamoon2/
