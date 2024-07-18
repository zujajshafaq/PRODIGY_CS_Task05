import os
import platform
import time
from scapy.all import sniff, wrpcap
from scapy.arch import get_if_list, get_windows_if_list

# Function to list available interfaces and select one
def list_interfaces():
    """
    List available interfaces and return the selected one.
    """
    system = platform.system()
    if system == 'Windows':
        interfaces = get_windows_if_list()
    elif system == 'Linux':
        # Use os.system to run ifconfig command and parse output to get interface names
        result = os.popen('ifconfig -s').readlines()
        interfaces = [line.split()[0] for line in result[1:] if line.strip()]  # Skip header line and extract interface names
    else:
        raise OSError(f"Unsupported OS: {system}. Only Windows and Linux are supported.")

    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        ifname = iface["name"] if system == 'Windows' else iface
        print(f"{i}. {ifname}")  # Display the index and name of each interface
    selected = -1
    while selected < 0 or selected >= len(interfaces):
        try:
            selected = int(input("Select an interface (0-based index): "))  # User selects an interface
        except ValueError:
            pass
    return interfaces[selected]["name"] if system == 'Windows' else interfaces[selected]

# Dummy packet handler function
def packet_handler(packet):
    """
    Dummy packet handler.
    """
    packet.show()  # Display packet information

# Parameters
DEVICE = list_interfaces()  # Get the selected interface
OUTPUT_FILE = "captured_packets.pcap"  # Output file name

try:
    print(f"Capturing packets on {DEVICE}. Press Ctrl+C to stop.")
    # Start capturing packets on the selected interface, call packet_handler for each packet, and store them in 'packets'
    packets = sniff(iface=DEVICE, prn=packet_handler, store=True)
except KeyboardInterrupt:
    print("Packet capture interrupted by user.")
    packets = []  # Empty list to handle interrupted capture

# Save packets to a file with timestamp in the filename
timestamp = time.strftime("%Y%m%d%H%M%S")
output_file_with_timestamp = f"captured_packets_{timestamp}.pcap"
wrpcap(output_file_with_timestamp, packets)

print(f"Packets saved to {output_file_with_timestamp}")
