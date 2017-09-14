import dpkt
import msgpack
import redis
import click
import socket
import pcap

@click.group()
def cli():
    pass

@click.command()
def stream_packets():
    pc = pcap.pcap()
    #pc.setfilter('udp dst port 53')
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    p = r.pubsub()
    try:
        for ts, pkt in pc:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            proto = ''
            plen = 0
            ip_version = ''
            ip_src = ''
            ip_dst = ''
            if eth.type == 2048:
                ip_version = 'ipv4'
                proto = ip.p
                plen = ip.len
                ip_src = socket.inet_ntoa(ip.src)  # 5
                ip_dst = socket.inet_ntoa(ip.dst)
            elif eth.type == 34525:
                ip_version = 'ipv6'
                proto = ip.nxt
                ip_src = socket.inet_ntop(socket.AF_INET6, ip.src)  # 5
                ip_dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
                #NOTE the non-fixed IPv6 headers should be subtracted from this value to get the actual payload size
                plen = ip.plen
            else:
                continue

            if proto == 6:
                proto ='tcp'
            elif proto == 17:
                proto = 'udp'

            r.publish('test', msgpack.packb({'ip_version': ip_version, 'proto' : proto, 'length' : plen, 'src_ip': ip_src, 'dst_ip' : ip_dst}))
    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass


if __name__ == "__main__":
    cli.add_command(stream_packets)
    cli()

