# idipv4
Security Tool

Description
-----------
The idipv4 is a simple but handy security tool for identifying foreign
destination IPv4 addresses found outside the US from a simple 
netstat output.  Uses rdap or whois (your choice in code). Outputs
to console and output file for redlisting.

Author: M.Guman  
Baseline 20190102

Notes:
------
Lookup performance (speed) varies based on your network configuration.


Requirements:
-------------
- Python3
- ipwhois package 
          

Syntax:
------- 
python3 idip.py -i <address_file> -o <redlist_output_filename>



Steps:
------
1) Execute 'netstat -an > netstat_data.txt' on windows or linux shell
2) python3 idip.py -i netstat_data.txt -o red_list.txt


Enjoy!


