"""
@Author: Jason.P
@Date: 2024-06-20 10:00:00
Scapy Ping Function
Usage: In Windows terminal (NOT VM): python scapy_ping.py <target_ip>
Coded with assistance of LLM IDE
"""

#general ping structure:
#craft IP header, ICMP Header(type 8 for echo request), Payload
#ICMP Header: Type, Code, Checksum, Identifier = 0xBEEF, Sequence Number
#ICMP(type=8, code=0, id=0x1234, seq=seq)



#Code Structure:
#Construct Payload
#Initialize counters
#Build packets x count
#send packets
#count total lost over count

import argparse
import sys
import time
from time import perf_counter
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
from scapy.packet import Raw
from scapy.all import conf
import socket

conf.verb = 0

def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f'Cannot resolve hostname {hostname}')
        sys.exit(1)

def scapy_ping(target_ip, count: int = 4, payload_size: int=32, timeout: float=2.0):
    payload = '0' * payload_size
    print(f"Pinging {target_ip} with {payload_size} bytes of data:")

    sent = 0
    received = 0
    time_list = []

    for i in range(1, count + 1):
        seq = i
        ICMP_Header = ICMP(type=8, code=0, id=0x1234, seq=seq)
        raw = Raw(load=payload)
        ip_pkt = IP(dst=target_ip)

        ICMP_Header.add_payload(raw)
        ip_pkt.add_payload(ICMP_Header)
        pkt = ip_pkt

        start_time = perf_counter()
        sent += 1
        reply = sr1(pkt, timeout=timeout) ## Actual packet sending / receiving
        end_time = perf_counter()
        rtt = (end_time - start_time) * 1000  # Convert to milliseconds
        if reply:
            received += 1
            time_list.append(rtt)
            print(f"Reply from {reply.src}: bytes={len(reply[Raw].load)} time={rtt:.2f}ms TTL={reply.ttl}")
            ttl = reply.ttl
        else:
            print("Request timed out.")
        
        # Add 1 second delay between pings (except for the last one)
        if i < count:
            time.sleep(1)
    lost = sent - received
    loss_percentage = (lost / sent) * 100
    print(f"\nPing statistics for {target_ip}:")
    print(f"    Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_percentage:.2f}% loss),")

    if time_list:
        min_time = min(time_list)
        max_time = max(time_list)
        avg_time = sum(time_list) / len(time_list)
        print(f"Approximate round trip times in milli-seconds:")
        print(f"    Minimum = {min_time:.2f}ms, Maximum = {max_time:.2f}ms, Average = {avg_time:.2f}ms")
    return


def main():
    parser = argparse.ArgumentParser(description="Ping a target using Scapy")
    parser.add_argument("target", help="Target IP address or domain (e.g., 8.8.8.8 or google.com)")
    parser.add_argument("-c", "--count", type=int, default=4, help="Number of echo requests to send (default: 4)")
    parser.add_argument("-s", "--size", type=int, default=32, help="ICMP payload size in bytes (default: 32)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="Timeout in seconds for each reply (default: 2.0)")
    args = parser.parse_args()

    resolved_ip = resolve_hostname(args.target)
    args.target = resolved_ip

    try:
        scapy_ping(args.target, args.count, payload_size=args.size, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nUser cancelled.")
        sys.exit(1)

if __name__ == "__main__":
    main()


#Questions: How did you resolve the domain name? 
####
# What function did you call? 
####
# What does it do? 
####
# Compare your solution with the built-in Ping command available from the command line. 
####
# What differences do you notice? Why are they different? 
####
# How could you make your code run faster?
