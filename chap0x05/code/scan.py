from scapy.all import *

def tcpconnect(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=timeout)
    # 无响应意味着目标主机的端口处于过滤状态
    if pkts is None:
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        # 0x012:(SYN,ACK)包证明端口开放
        if(pkts.getlayer(TCP).flags == 0x12):
            #发送ACK确认包
            send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="AR"),timeout=timeout)
            print("Open")
        # 0x014:(RST,ACK)包证明端口关闭
        elif (pkts.getlayer(TCP).flags == 0x14):   
            print("Closed")

# 连接靶机
tcpconnect('172.16.111.141', 80)