# BASIC-NETWORK-SNIFFER
task 1

from scapy.all import sniff, wrpcap

interface = "eth0"

#  function to analyze 
def analyze_packet(packet):

  # Print basic 
  print(f"Source: {packet[IP].src}")
  print(f"Destination: {packet[IP].dst}")
  print(f"Protocol: {packet[IP].proto}")

  # Access specific layers
  if packet.haslayer(TCP):
    print(f"Source Port: {packet[TCP].sport}")
    print(f"Destination Port: {packet[TCP].dport}")

  # Write additional logic to analyze data payload or other packet details

# Capture packets and call the analyze function for each packet
print(f"Sniffing traffic on interface {interface}...")
sniff(iface=interface, prn=analyze_packet, store=False)


print("Sniffing complete!")

