parallel_nmap.py

parallel running nmap scans (speed up), after a quick nmap ping scan (discovery)

--------------------------------------------------------------------------------

parallel_nmap_portscan_only.py

parallel running nmap scans (speed up), no discovery

--------------------------------------------------------------------------------

### Windows 11 Install
##### install nmap
https://nmap.org/download#windows

##### install python
https://www.python.org/downloads/
#say yes to "install on path"

##### install nmap on path
win + r sysdm.cpl > Advanced > Environment Variables > New > _ > OK > OK
- Variable name: nmap.exe
- Variable value: C:\Program Files (x86)\Nmap\nmap.exe

win + r sysdm.cpl > Advanced > Environment Variables > System variables > Path > Edit > Browse Directory > C:\Program Files (x86)\Nmap\
- Variable name: nmap.exe
- Variable value: C:\Program Files (x86)\Nmap\

##### run scanner
powershell

cd C:\Users\$Env:UserName\Desktop

python parallel_nmap_portscan_only.py -t 192.168.0.0/24 -a "-sV -sT -T5 -p- --host-timeout 30s --max-rtt-timeout 30s --initial-rtt-timeout 30s"

type nmap.txt #results

On my network "192.168.0.0/24" it takes a minute to scan.
