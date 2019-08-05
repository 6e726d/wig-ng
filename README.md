# wig-ng
WIG (WiFi Information Gathering) is a free and open source utility for WiFi device fingerprinting.

## Requirements
 - pcapy
 - impacket

### Installation

**$** sudo pip install pcapy  
**$** sudo pip install impacket  
**$** git clone https://github.com/6e726d/wig-ng.git

## Supported Protocols & Standards

 - Apple Wireless Direct Link (AWDL)
 - Cisco Client Extension (CCX)
 - HP Printers Custom Information Element
 - Wi-Fi Direct (P2P)
 - WiFi Protected Setup (WPS)

## Usage

<pre>
usage: wig-ng.py [-h] [-v] [-c count] [-a]  
                 (-i network interface | -r pcap file | -R pcap directory)  
  
optional arguments:  
  -h, --help            show this help message and exit  
  -v, --verbose         Output verbosity (incremental).  
  -c count, --concurrent count  
                        Number of PCAP capture files to process  
                        simultaneously.  
  -a, --active          Some modules can perform frame injection, this is  
                        define by setting the active mode.  
  -i network interface, --interface network interface  
                        IEEE 802.11 network interface on monitor mode.  
  -r pcap file          PCAP capture file with IEEE 802.11 network traffic.  
  -R pcap directory     Directory with PCAP capture files.  
</pre>

## Usage Examples

**$** sudo iwconfig \<iface\> mode monitor  
**$** sudo ifconfig \<iface\> up  
**$** cd wig-ng  
**$** sudo python wig-ng.py -i \<iface\>

## Notes

 - This tools doesn't perform channel hopping, use a tools such as [chopping](https://github.com/6e726d/chopping) or [airodump-ng](https://www.aircrack-ng.org/).
