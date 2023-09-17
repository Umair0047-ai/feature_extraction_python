import csv
import pyshark
import pyshark
import subprocess
import time
import pickle
import pandas as pd

def protocol_number(pcap_file):
        count = 0
        tcp_protocol_num = []
        udp_protocol_num = []
        icmp_protocol_num = []
        count = 0 
        capture = pyshark.FileCapture(pcap_file)
        for packet in capture: 

            """ if count == 18000: ##  to take the packet size of maximum 18000 because processing takes alot time
                break
            count = count + 1 """
            if "TCP" in packet or "UDP" in packet or "ICMP" in packet:
                if "TCP" in packet:
                    tcp_protocol_num.append(6)
                else:
                    tcp_protocol_num.append(0)

                if "UDP" in packet:
                    udp_protocol_num.append(17)
                else:
                    udp_protocol_num.append(0)

                if "ICMP" in packet:
                    icmp_protocol_num.append(1)
                else:
                    icmp_protocol_num.append(0)
            else:
                    tcp_protocol_num.append(0)
                    udp_protocol_num.append(0)
                    icmp_protocol_num.append(0) 

        return tcp_protocol_num,udp_protocol_num,icmp_protocol_num

def src_dst_port(pcap_file):
    tcp_src = []
    tcp_dest = []
    udp_src = []
    udp_dest = []
    count = 0
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        """ if count == 18000:  ##  to take the packet size of maximum 18000 because processing takes alot time
            break
        count = count + 1
         """
        if 'TCP' in packet:    
            tcp = packet['TCP']
            tcp_src.append(tcp.srcport)
            tcp_dest.append(tcp.dstport)
        else:
            tcp_src.append(0)
            tcp_dest.append(0)
        if 'UDP' in packet:
            udp = packet['UDP']
            udp_src.append(udp.srcport)

            udp_dest.append(udp.dstport)  
        else:
            udp_src.append(0)
            udp_dest.append(0)
    return tcp_src,tcp_dest,udp_src,udp_dest      
         
         
### Get the relative_time 
def relative_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    time_relative_tcp = []
    time_relative_udp = []
    time = []
    count = 0
    for packet in capture:
        """ if count == 18000:  ##  to take the packet size of maximum 18000 because processing takes alot time
            break
        count = count + 1 """
        if 'tcp' in packet:    
            if hasattr(packet.tcp, "time_relative"):
                time_since_first_frame = float(packet.tcp.time_relative)
                time_relative_tcp.append(time_since_first_frame)
        else:
            time_relative_tcp.append(0)
        if 'udp' in packet:
            if hasattr(packet.udp, "time_relative"):   
                time_since_first_frame = float(packet.udp.time_relative)
                time_relative_udp.append(time_since_first_frame)   
        else:
            time_relative_udp.append(0)
        
        data = packet.frame_info.time_delta_displayed
        time.append(data)
        
    return time,time_relative_tcp,time_relative_udp
        

## function to get the time to live (Manually) 
def get_ttl(pcap_file):
    ttl = []
    count = 1
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        """ if count == 18000: ## to take the packet size of maximum 18000 because processing takes alot time
            break
        count = count + 1 """
        if "IP" in packet:
            ip = packet["IP"]
            ttl.append(ip.ttl)
        else:
            ttl.append(0)
    return ttl

def get_packet_length(packet_data):
    return len(packet_data)


def tot_length(pcap_file):
    length = []
    count = 0
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
         """ if count == 18000: ## to take the packet size of maximum 18000 because processing takes alot time
            break
         count = count + 1 """
         a = str(get_packet_length(packet))
         length.append(int(a))
    return length

### Function for reading protocol TCP,UDP,ICMP,icmp
def read_protocol_packet(pcap_file):
    
     
    TCP = []    
    UDP = []    
    ICMP = []
    
    count = 0
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        """ if count == 18000: ##to take the packet size of maximum 18000 because processing takes alot time
            break
        count = count + 1 """
        if 'TCP' in packet or 'UDP' in packet or 'ICMP' in packet: 
            if 'TCP' in packet:
                TCP.append(1)
            else:
                TCP.append(0)
            if 'UDP' in packet:
                    UDP.append(1)
            else:
                UDP.append(0)
            if 'ICMP' in packet:
                ICMP.append(1)
            else:
                ICMP.append(0)

        else:
                TCP.append(0)
                ICMP.append(0)
                UDP.append(0)
    
    return TCP,UDP,ICMP    


### function for reading flags
def read_flags(pcap_file):
    
    SYN = [] 
    FIN = [] 
    ACK = []
    RST = []
    ECE = []
    CWR = []
    count = 0
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        """ if count == 18000:  ##to take the packet size of maximum 18000 because processing takes alot time
            break
        count = count + 1 """
        if 'IP' in packet and 'TCP' in packet:
            #ip = packet['IP']
            tcp = packet['TCP']

            if int(tcp.flags_syn):
                SYN.append(1)
            else:
                SYN.append(0)
            if int(tcp.flags_fin):
                FIN.append(1)
            else:
                FIN.append(0)
            if int(tcp.flags_ack):
                ACK.append(1)
            else:
                ACK.append(0)
            if int(tcp.flags_reset):
                RST.append(1)
            else:
                RST.append(0)
            if int(tcp.flags_ece):
                ECE.append(1)
            else:
                ECE.append(0)
            if int(tcp.flags_cwr):
                CWR.append(1)
            else:
                CWR.append(0)
        else:
            SYN.append(0)
            FIN.append(0)
            ACK.append(0)
            RST.append(0)
            ECE.append(0)
            CWR.append(0)
    return SYN,FIN,ACK,RST,ECE,CWR

def run_captures():
    

    interface = "wi-fi"  # Replace with the actual interface name
    capture_duration = 60  # Capture duration in seconds

    # Construct the tshark command
    command = [
        "tshark",
        "-i", interface,
        "-w", "captured_packets.pcap",
        "-a", f"duration:{capture_duration}"
    ]

    # Run the tshark command
    subprocess.run(command)
    

### Saving features into a file
def feature_extracted(timestamps,SYN,FIN,ACK,RST,ECE,CWR,TCP,UDP,ICMP,max_len,ttl,relative_time_tcp,relative_time_udp,tcp_src,tcp_dest,udp_src,udp_dest,tcp_protocol_num,udp_protocol_num,icmp_protocol_num,output_file):
    with open(output_file,'w',newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['timestamp','SYN','FIN','ACK','RST','ECE','CWR','TCP','UDP','ICMP','max_len','ttl','relat_time_tcp','relat_time_udp','tcp_src','tcp_dest','udp_src','udp_dest','tcp_protocol_num','udp_protocol_num','icmp_protocol_num'])
        for timestamp,SYN,FIN,ACK,RST,ECE,CWR,TCP,UDP,ICMP,max_len,ttl,relative_time_tcp,relative_time_udp,tcp_src,tcp_dest,udp_src,udp_dest,tcp_protocol_num,udp_protocol_num,icmp_protocol_num in zip(timestamps,SYN,FIN,ACK,RST,ECE,CWR,TCP,UDP,ICMP,max_len,ttl,relative_time_tcp,relative_time_udp,tcp_src,tcp_dest,udp_src,udp_dest,tcp_protocol_num,udp_protocol_num,icmp_protocol_num):
            csvwriter.writerow([timestamp, SYN,FIN,ACK,RST,ECE,CWR,TCP,UDP,ICMP,max_len,ttl,relative_time_tcp,relative_time_udp,tcp_src,tcp_dest,udp_src,udp_dest,tcp_protocol_num,udp_protocol_num,icmp_protocol_num])
    

if __name__ == '__main__':


    #run_captures()     ## This is the function for running tshark command this open cmd and gets the live captures generates the pcap file then it is fed to script
    #print("Real time packets have been captured!!!")                 ## and the script then converts it into csv file
    
    time.sleep(5)

    pcap_file = 'captured_packets.pcap'
    output_csv = 'test.csv'

    tcp_protocol_num,udp_protocol_num,icmp_protocol_num = protocol_number(pcap_file)
    
    tcp_src,tcp_dest,udp_src,udp_dest = src_dst_port(pcap_file)
      
    timestamp,relative_time_tcp,relative_time_udp = relative_pcap(pcap_file)
   
    max_len = tot_length(pcap_file)
    
    ttl =  get_ttl(pcap_file)

    TCP,UDP,ICMP = read_protocol_packet(pcap_file)
    
    SYN,FIN,ACK,RST,ECE,CWR = read_flags(pcap_file)
    
    feature_extracted(timestamp,SYN,FIN,ACK,RST,ECE,CWR,TCP,UDP,ICMP,max_len,ttl,relative_time_tcp,relative_time_udp,tcp_src,tcp_dest,udp_src,udp_dest,tcp_protocol_num,udp_protocol_num,icmp_protocol_num,output_csv)    
   


print(f"timestamps saved to {output_csv}")
time.sleep(5)

    ## using pickle file to load the trained model

loaded_model = pickle.load(open('Classifying-attacks.pkl','rb'))
test = pd.read_csv('test.csv')

print(loaded_model.predict(test))