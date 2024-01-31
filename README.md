# firewall-bypass
Allows you to download data from the Internet without permission, using other processes. It may be marked as malware. 
### How it works  
 1) Search for processes with an Internet connection
 2) Injection the shellcode into a target process
 3) Downloading data from the Internet in the target process
 4) Sending the downloaded data from the target process to the executing process
### Status
| Name | Status | Comment
| :-: | :-: | :-:
| Windows Firewall | + | Fully
| Comodo Firewall | ± | Blocked by [HIPS](https://en.wikipedia.org/wiki/Intrusion_detection_system)
| [Simplewall](https://github.com/henrypp/simplewall) | + | Fully
| [TinyWall](https://github.com/pylorak/TinyWall) | + | Fully
| ZoneAlarm | + | Fully
| GlassWire | + | Fully (Logged)
