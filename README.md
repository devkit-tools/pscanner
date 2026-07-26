PASSIVE NETWORK SENSOR — TARGET LIST EXPORT
#
#
#
REQUIRED Python libs are scapy & manuf

python3 -m pip install scapy

python3 -m pip install manuf#
command
#
#
#
sudo python3 pscanner.py -i en0 -t 5



Command flags:

  
  -i is the network interface
  
  -t refresh time in seconds
 


Generated target lists in:
  passive_report/targets.txt --- targets_ipv4.txt --- targets_ipv6.txt


Examples for futher scans:

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
