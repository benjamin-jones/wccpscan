import csv
import wccplib as wlib
from optparse import OptionParser
import binascii
from scapy.all import wrpcap, Ether, IP, UDP

parser = OptionParser()
parser.add_option("-o", "--output", dest="outputfile", help="Output file")
parser.add_option("-i", "--input", dest="inputfile", help="Input file")

(options, args) = parser.parse_args()


def validate_response(response):
    try:
        isy = wlib.wccp_isy_message(response)
    except:
        return "DID NOT VALIDATE"
    return "VALID"


if options.inputfile and options.outputfile:
    fp = open(options.inputfile, "r")
    data = csv.DictReader(fp)
    wccp_servers = []
    packets = []
    for row in data:
        if "VALID" == validate_response(binascii.unhexlify(row["data"])):
            wccp_servers.append(row)
    print("Got %d valid responses, generating pcap" % len(wccp_servers))
    for server in wccp_servers:
        ip = server["saddr"]
        payload = binascii.unhexlify(server["data"])
        packet = Ether() / IP(src=ip) / UDP(dport=2048, sport=2048) / payload
        packets.append(packet)
    wrpcap(options.outputfile, packets)
else:
    print("Usage: ./wccp2pcap -i <zmap csv> -o <pcap file>")

