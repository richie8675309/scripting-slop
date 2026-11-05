# Simple Traffic Monitor

A standalone traffic monitor using windows built-in packet sniffing tool `pktmon`. 

The monitor sends public IP addresses to https://ipwho.is for network information. A hostname, company name, or country is a clue about the network.
## How to use

In the `traffic-monitor` folder, simply run `traffic-monitor.ps1` or `traffic-monitor.exe` as administrator.

This will create a `traffic-logs` folder which will contain following:<br>
`flows.csv` - A timestamped NEW entry when a flow is first seen, and EXPIRED when it has been inactive for 5 minutes; includes packet counts and addresses. <br>
`lookups.csv` - Results of IP information requests: hostname, provider, ASN, country, and errors. <br>
`lookup-cache.json` - Saved lookup results and daily request count so the app doesn't keep looking up the same IP. <br>
`pktmon-output.txt`- Raw text output received from PktMon; useful for troubleshooting. <br>
`PktMon.etl` - Recorded packets captured by pktmon. <br>
`error.log` - Problems encountered by the monitor.

When running, will display a table of unique traffic:

In the image above:
`10.2.2.2` my local VPN IP address.<br>
`224.0.0.252` OS systemd-resolved (local UDP network traffic)<br>
`172.64.155.209` Cloudflare IP address (DNS server)<br>


If pktmon failed to clean up in the background run this command in an elevated powershell window:
```
pktmon stop
```


This script is mainly targeted at users that aren't that tech savy and can't be bothered with wireshark.