# find_interfaces.py
from scapy.all import get_if_list

print("Available network interfaces according to Scapy:")
print("=" * 50)

interfaces = get_if_list()
for i, iface in enumerate(interfaces, 1):
    print(f"{i}. {iface}")

print("\n" + "=" * 50)
print("For localhost testing, look for something like:")
print("- 'Loopback' or 'lo' (Linux style)")
print("- 'Loopback Pseudo-Interface' (Windows)")
print("- 'lo0' (Mac)")
print("\nTry these in your config.py:")
for iface in interfaces:
    if "loop" in iface.lower() or "lo" in iface.lower():
        print(f"NETWORK_INTERFACE = \"{iface}\"")