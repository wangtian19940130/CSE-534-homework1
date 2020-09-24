Dear Instructor/TA:

The code corresponding to PART A is "mydig.py" and the sample output is "mydig_output.txt". This program can retrieve three types of DNS records of a website, i.e., "A", "NS", and "MX". For example, to retrieve the IPV4 address of google.com, the input in cmd terminal is: "python mydig.py google.com A". 
	In case of DNS hijack, "mydig_tcp.py" uses TCP to send DNS query messages while the other part is totally the same with "mydig.py". When I used "mydig.py" to resolve the "NS" and "MX" records of "google.com" without a VPN, I found that this program get a response from the ISP which only indicated the "A" record other than a response from the root server. Thus the records though correctly resolved may also be sent by the ISP other than the DNS servers listed in the program.
	
The code corresponding to PART B is "mydig_dnssec.py" and the sample output is "mydig_dnssec_output.txt". This program can retrieve only "A" record of a website and tell whether this website support DNSSEC and whether the DNSSEC verification is successful. There will be three cases about the DNSSEC configuration and verification. 
	This program will always output the IP address (even the website doesn't support DNSSEC, people still need to visit the website) and tell whether it is a verified IP address. An example of program input in the cmd terminal is: "python mydig_dnssec.py verisigninc.com".

The libraries used in the programs are:
	import dns.name
	import dns.query
	import dns.resolver
	import sys
	import time
	import threading 
	import matplotlib.pyplot as plt

The implementation of DNSSEC can be found in "B.pdf" and the experiment results and analysis in PART C can be found in "C.pdf".

In fact, the ISP China Telecom always tries to hijack the DNS resolution much because the ISP wants to accelerate the DNS resolution. Sending query with TCP or using VPN seems to be able to avoid such hijack. But I still doubt the results in PART C. 