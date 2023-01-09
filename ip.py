import pyshark
import ipapi
import socket
import os 

tos = """
By using this script, you agree to use it only for educational purposes.
- You understand that you are solely responsible for any action you take using this script and that the creator of this script is not responsible for any consequences you may have as a result of using this script.
- Use at your own risk. Copyright from NeverHit 2019-2023
"""
print(tos)

agree = input("Continue? [y/n]: ")

if agree.lower() != "y":
    exit()

if os.name == "nt": #Binbows
    os.system("cls")
else: # Linux
    os.system("clear")
local_ip = socket.gethostbyname(socket.gethostname())
print("Creating capture object")
capture = pyshark.LiveCapture(interface='#YOUR INTERFACE HERE')
print("Sniffing packets...")
destination_ips = set()

for packet in capture.sniff_continuously():
    if packet.transport_layer != "UDP":
        continue
    
    if "CLASSICSTUN Layer" in str(packet.layers):
        if packet.ip.src in destination_ips or packet.ip.dst in destination_ips:
            continue
        else:
            print("Adding IP to ignore list")
            destination_ips.add(packet.ip.dst)
            src_location = ipapi.location(ip=packet.ip.src)
            dst_location = ipapi.location(ip=packet.ip.dst)
            if packet.ip.src == local_ip:
                print(f'Source: {packet.ip.src} (You)')
            else:
                print(f'Source: {packet.ip.src}')
            if 'country_name' in src_location:
                print(f'Location: {src_location["country_name"]}, {src_location["city"]}, {src_location["region"]}')
            else:
                print(f'Location: Unknown')
            print(f'Destination: {packet.ip.dst}')
            if 'country_name' in dst_location:
                print(f'Location: {dst_location["country_name"]}, {dst_location["city"]}, {dst_location["region"]}')
            else:
                print(f'Location: Unknown')
            max_length = max(len(packet.ip.src), len(packet.ip.dst))
            if 'country_name' in src_location:
                max_length = max(max_length, len(src_location['country_name']), len(src_location['city']), len(src_location['region']))
            if 'country_name' in dst_location:
                max_length = max(max_length, len(dst_location['country_name']), len(dst_location['city']), len(dst_location['region']))
            print('-' * max_length)
            print()

#It just took me 5 minutes to do it, and if you don't know how to get him to work, I thought maybe you could go search for how to use py files