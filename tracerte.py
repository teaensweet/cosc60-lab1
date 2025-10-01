from scapy.all import *
import sys
import socket

# traceroute program that takes the target's IP address or hostname as an imput from the command line

def traceroute(target):
    for i in range(1,28):
        pckt = IP(dst=target, ttl=i)/ICMP(id=123, seq=i)
        reply = sr1(pckt, timeout=2, verbose=0)
        if reply is None:
            print(f"packet {i}: * * * Request timed out")
            continue
        if reply.type == 0:
            print(f"packet {i}: received a reply from {reply.src}")
            reply.show()
            break
        elif reply.type == 11:
            print(f"packet {i}: travel-time expired from {reply.src}")

# resolve hostname using socket
def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f'Cannot resolve hostname {hostname}')
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        hostname = sys.argv[1]
        target_ip = resolve_hostname(hostname)
        traceroute(target_ip)
    else:
        print('target network necessary')


#Questions: What could happen to cause an inconsistency in the route you discover? How likely is that to happen while your program runs?
####Network congestion, routing changes, or packet loss could cause inconsistencies in the route discovered. These events can happen frequently in dynamic networks, especially over longer periods or during peak usage times.
####However, during a short run of the program, the likelihood of significant route changes is relatively low, but not impossible.