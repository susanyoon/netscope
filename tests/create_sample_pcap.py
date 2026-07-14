from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap

packets = [
    Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=80),
    Ether() / IP(src="192.168.1.20", dst="1.1.1.1") / UDP(sport=54321, dport=53),
    Ether()
    / IP(src="192.168.1.30", dst="8.8.4.4")
    / UDP(sport=40000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com")),
]

wrpcap("tests/sample.pcap", packets)

print("Created tests/sample.pcap")
