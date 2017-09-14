import dpkt
import msgpack
import redis
import click
import socket
import pcap

@click.group()
def cli():
    pass

def stream(pc):
    """
    pc should iterate over packets

    :param pc:
    :return:
    """

    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    p = r.pubsub()

    try:
        for ts, pkt in pc:
            eth = dpkt.ethernet.Ethernet(pkt)
            data = {}
            ip = eth.data
            if eth.type == 2048:  # only process IPv4
                data['timestamp'] = ts
                data['ip_ttl'] = ip.ttl
                data['ip_proto'] = ip.p
                data['ip_length'] = ip.len
                data['ip_src'] = socket.inet_ntoa(ip.src)  # 5
                data['ip_dst'] = socket.inet_ntoa(ip.dst)

                if (ip.p == 6 or ip.p == 17):  # Only add data for TCP or UDP
                    proto = ip.data
                    data['sport'] = proto.sport  # 7
                    data['dport'] = proto.dport  # 8
                    tcp_flag = ""
                    if ip.p == 6:
                        try:
                            tcp_flag += ("F" if (int(proto.flags & dpkt.tcp.TH_FIN) != 0) else ".")  # 27
                            tcp_flag += ("S" if (int(proto.flags & dpkt.tcp.TH_SYN) != 0) else ".")  # 26
                            tcp_flag += ("R" if (int(proto.flags & dpkt.tcp.TH_RST) != 0) else ".")  # 25
                            tcp_flag += ("P" if (int(proto.flags & dpkt.tcp.TH_PUSH) != 0) else ".")  # 24
                            tcp_flag += ("A" if (int(proto.flags & dpkt.tcp.TH_ACK) != 0) else ".")  # 23
                            tcp_flag += ("U" if (int(proto.flags & dpkt.tcp.TH_URG) != 0) else ".")  # 22
                            tcp_flag += ("E" if (int(proto.flags & dpkt.tcp.TH_ECE) != 0) else ".")  # 21
                            tcp_flag += ("C" if (int(proto.flags & dpkt.tcp.TH_CWR) != 0) else ".")  # 20
                        except:
                            pass
                        data['tcp_flag'] = tcp_flag
                        if (proto.dport == 80) or (proto.dport == 443):
                            http_request_method = ''
                            if not proto.data == '':
                                try:
                                    http_request_method = dpkt.http.Request(proto.data).method
                                except:
                                    http_request_method = ''
                            data['http_data'] = http_request_method

                    fragments = 1 if (
                        int(
                            ip.off & dpkt.ip.IP_MF) != 0) else 0  # 8 This flag is set to a 1 for all fragments except the last one
                    data['fragments'] = fragments

                # elif eth.type == 34525:
                #     ip_version = 'ipv6'
                #     proto = ip.nxt
                #     ip_src = socket.inet_ntop(socket.AF_INET6, ip.src)  # 5
                #     ip_dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                #     #NOTE the non-fixed IPv6 headers should be subtracted from this value to get the actual payload size
                #     plen = ip.plen

                # if proto == 6:
                #     proto ='tcp'
                # elif proto == 17:
                #     proto = 'udp'

                r.publish('packets', msgpack.packb(data, use_bin_type=False))
            else:
                continue

    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass


@click.command()
@click.argument('filename')
def stream_pcap(filename):
    with open(filename, 'r') as f:
        #inputfile = open(filename , 'r')
        pc = dpkt.pcap.Reader(f)

        stream(pc)

@click.command()
def stream_packets():
    pc = pcap.pcap()
    #pc.setfilter('udp dst port 53')
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    p = r.pubsub()
    stream(pc)


if __name__ == "__main__":
    cli.add_command(stream_packets)
    cli.add_command(stream_pcap)
    cli()

