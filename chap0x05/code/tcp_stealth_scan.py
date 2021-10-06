from scapy.all import *


def tcpstealthscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    # 无响应意味着目标主机的端口处于过滤状态
    if (pkts is None): 
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        # 0x012:(SYN,ACK)包证明端口开放
        if(pkts.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        # 0x014:(RST,ACK)包证明端口关闭
        elif (pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
        # 两种不可达情况
        elif(pkts.haslayer(ICMP)):
            if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered")

# 连接靶机
tcpstealthscan('172.16.111.141', 80)