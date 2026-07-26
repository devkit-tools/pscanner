# PASSIVE NETWORK SENSOR — TARGET LIST EXPORT

## Required Python libraries

```bash
python3 -m pip install scapy
python3 -m pip install manuf
```

## Command

```bash
sudo python3 pscanner.py -i en0 -t 5
```

## Command flags

`-i` is the network interface

`-t` refresh time in seconds

## Generated target lists

```text
passive_report/targets.txt
passive_report/targets_ipv4.txt
passive_report/targets_ipv6.txt
```

## Examples for further scans

### Nmap

```bash
nmap -iL passive_report/targets_ipv4.txt
```

### Nmap service scan

```bash
nmap -sV -iL passive_report/targets_ipv4.txt
```

### Masscan

```bash
sudo masscan -iL passive_report/targets_ipv4.txt -p1-65535 --rate 1000
```
