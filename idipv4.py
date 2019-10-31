#! /usr/bin/env python3
#######################################################################
# idipv4 - Simple but handy security tool for identifying foreign
#          IPv4 addresses found in a netstat output (Linux or Windows)
#          Uses rdap or whois (your choice). Lookup performance (speed) 
#          varies based on your network configuration.
#
# Author: M.Guman
#
# History:  20190102 Baseline 
#           
# External Dependencies: ipwhois package (pip3 install ipwhois)
# 
#######################################################################
import os
import re
import sys
import csv
import getopt
import argparse
import datetime
from ipwhois import IPWhois


_country_codes = {}

def load_country_codes(ccFileName):
    if not os.path.exists(ccFileName):
       print ("Could not load country codes.")
    else:   
        with open(ccFileName, 'r') as csvDataFile:
            csvReader = csv.reader(csvDataFile)
            for row in csvReader:
                if len(row) >= 2:
                    entry = row
                    try:
                        _country_codes[entry[1]] = entry[0]
                    except:
                        print("CC format error:" + entry[0] + ":" +entry[1])


def check_country(addresses):
    redlist = []
    if addresses is not None:
        for address in addresses:
            try:
                print ("ADDRESS: {}\t".format(str(address)),end='',flush=True)
                obj=IPWhois(address)
                obj.timeout=5
                       
                # make your own choice, try rdap or whois                     
                res = obj.lookup_rdap()
                #res=obj.lookup_whois()
                
                
                # excerpt from ipwhois v0.12.0 documentation March 28, 2016:
                #
                # IPWhois.lookup_rdap() is now the recommended lookup method. RDAP provides a far better 
                # data structure than the old legacy whois and REST lookups (previous implementation). RDAP queries
                # allow for parsing of contact information and details for users, organizations, and groups. 
                # RDAP also provides more detailed network information.
                 
                country = str(res["asn_country_code"])
                desc = str(res["asn_description"])
                
                if country in _country_codes.keys():
                    codedesc = _country_codes[country]
                else:
                    codedesc = "<not listed>"
                print ("-- COUNTRY: {}  ({}) -- DESC: {}".format(country,codedesc,desc)   )  # get asn_country_code  asn_description
                
                if country != "US":
                    tup = (address,country)
                    redlist.append(tup)
            except:
                print (" -- Skipped")
             
    return redlist
  
  
def load_addresses(addressfile):
    addresses = []
    entry = ()

    m = re.compile(' +([udptcpUDPTCP])+  *([0-9])*  *([0-9])*  +([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)   +(?P<dest>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)  +([LAST_ACKCLOSE_WAITESTABLISHEDLISTENING]+)') 
    with open(addressfile,'r') as f:
        entry = f.readline()
        while entry:
            b=m.match(entry)
            if b is not None:
                dest_address=b.group('dest')
                addresses.append(dest_address)  
            entry = f.readline()
    return addresses
     

def print_redlist(redlist,redfilename):
    print ("\nIP Red List for originations outside US:")
    print ("------------------------------------------")
    
    if redlist is not None:
        # dump to red list file
        with open(redfilename, 'w') as f:
            # Check if no entries found
            if len(redlist) == 0:
                print("No external addresses found.")
                f.write("No external addresses found.")
            else:
                for (address,country) in redlist:
                    if country in _country_codes.keys():
                        codedesc = _country_codes[country]
                    else:
                        codedesc = "<not listed>"
                    #
                    print(address + "," + country +"," + codedesc)
                    f.write(address + "," + country +"," + codedesc)


def print_syntax():
    print ("\n-------------------------------------------------------------------------")
    print (" idipv4 - Simple but handy security tool for identifying foreign")
    print ("          IPv4 addresses found in a netstat output (Linux or Windows)")
    print ("          Lookup performance (speed) may vary based on your network ")
    print ("          configuration.\n\n")         
    print ("Syntax: python3 idip.py -i <address_file> -o <redlist_output_filename>\n\n")
    

    print ("Address file format is the output from a 'netstat -an'. \nLinux or Windows formats are supported.\n")
    print ("Note: Requires ipwhois package use (pip3 install ipwhois) to install.")
    print ("-------------------------------------------------------------------------")
   
   
def main(argv):
    try:     
        opts, args = getopt.getopt(argv,"hi:o:")           
    except getopt.GetoptError:
        print_syntax()
        sys.exit(2)
        
    # Validate args  
    if len(opts) != 2:
        print_syntax()
        sys.exit(2) 
        
    # Parse arguments
    for opt, arg in opts:
        #help
        if opt == '-h':
            print_syntax()
            sys.exit()
        elif opt in ("-i", "--input"):
            inputFile = arg
        elif opt in ("-o", "--output"):
            redFileNameOutput = arg
        
    if not os.path.exists(inputFile):
        print("Address file does not exist")
        print_syntax()
        sys.exit(2)    
    else:
        start = datetime.datetime.now()  
        print ("Processing....please wait.\n\n")       
        load_country_codes("country_codes.txt")
        print_redlist(check_country(load_addresses(inputFile)), redFileNameOutput)
        end = datetime.datetime.now()
        print("\nTotal query execution time: {}".format(end - start))

if __name__ == "__main__":
    main(sys.argv[1:])
    print("Complete.")
    exit(0)








