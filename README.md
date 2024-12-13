# ep_dwm
Implements a Windows service that removes the rounded corners for windows in Windows 11.

Tested on Windows 11 build 22000.434.

Pre-compiled binaries are available in the [ExplorerPatcher](https://github.com/valinet/ExplorerPatcher/releases) setup program (download the latest pre-release). You can install that program - it already includes this functionality built-in. Alternatively, to get only `ep_dwm.exe` from the downloaded `ep_setup.exe`, run this:

```
ep_setup /extract C:\ep_dwm
```

The executable will be extracted in `C:\ep_dwm`. If you do not need them, you can delete the rest of the files in there and keep only `ep_dwm.exe`.

To register, type these commands in an elevated command window:

```
sc.exe create ep_dwm binPath= "C:\ep_dwm\ep_dwm.exe ep_dwm Global\ep_dwm" DisplayName= "ep_dwm" start= auto
sc.exe description ep_dwm "ep_dwm Service"
sc.exe start ep_dwm
```

To unregister, type these commands in an elevated command window:

```
sc.exe stop ep_dwm
sc.exe delete ep_dwm
```

