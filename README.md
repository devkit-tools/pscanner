PASSIVE NETWORK SENSOR — TARGET LIST EXPORT
.
.
.
Start:
.
  sudo python3 pscanner.py -i en0 -t 5
.


Command flags:
  
  -i is the network interface
  
  -t refresh time in seconds
 


Generated target lists:
  passive_report/targets.txt
  passive_report/targets_ipv4.txt
  passive_report/targets_ipv6.txt


Examples:

Nmap:
  nmap -iL passive_report/targets_ipv4.txt

Nmap service scan:
  nmap -sV -iL passive_report/targets_ipv4.txt

Masscan:
  sudo masscan -iL passive_report/targets_ipv4.txt -p1-65535 --rate 1000

Important:
  The target files contain only hosts observed passively by the monitor.
  One IP address is written per line.
  Duplicate addresses are removed automatically.
