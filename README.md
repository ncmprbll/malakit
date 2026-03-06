# Malakit
Malakit (**mal**ware **a**nalysis **kit**) is both a CLI utility and a library whose purpose is to simplify some of a boilerplate you come across when working with Windows's API.

The name sounds almost like *malachite* and it is also misleading. That is, you're not obliged to use it for malware analysis. It should suffice for any other goals you have in mind!

# Usage
## Library
Refer to the documentation.

## CLI
```
PS > .\malakit.exe ps
0     [System Process]
4     System
...
33736 Code.exe
...
PS > .\malakit.exe scan 33736 "F8 C4 32 02 DB CA 2E ?? FA C4 59 02 ?? C7"
0x17ACBC20000 +0x1695DC
PS > .\malakit.exe scan 33736 --size 512 "F8 C4 32 02 DB CA 2E ?? FA C4 59 02 ?? C7"
0x17ACBC20000 +0x1695DC
```
