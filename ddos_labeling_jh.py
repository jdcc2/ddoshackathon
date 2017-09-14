import sys
import pandas as pd 
import numpy as np 
import dpkt
import socket
import time
import os
import click
from pprint import pprint


@click.group()
def cli():
    pass

@click.command()
@click.option('--max_ttl_perc', default=100)
@click.option('--min_source_ips', default=500)
@click.option('--min_traffic_perc', default=90)
@click.option('--min_traffic_mb', default=1000)
@click.argument('input', nargs=-1)

def search(input, max_ttl_perc, min_source_ips, min_traffic_perc, min_traffic_mb):
    filtered = 0
    no_data = 0
    fn_string = ""
    for fn in input:
        df = read_pcap_df(fn)
        if df.size <= 0:
            print("empty pcap: " + fn)
            continue
        result = analyse(df, os.path.split(fn)[1])
        #Check the share of IPS that have a high TTL variation
        if result is not None:
            ttl_violations_percentage = sum([ ip_count for ip_count, ttl in result["ttl_variation"].items() if ttl > 4]) / result["nr_src_ips"] * 100
            if ttl_violations_percentage < max_ttl_perc \
                and result["nr_src_ips"] > min_source_ips \
                and result["traffic_share"] > min_traffic_perc \
                and result["raw_attack_size_megabytes"] > min_traffic_mb:
                pprint(result)
                fn_string = fn_string + " " + fn
            else:
                filtered += 1
        else:
            no_data += 1

    print(str(filtered) + " attacks filtered")
    print(str(no_data) + " captures without attack patterns")
    print(fn_string)

@click.command()
@click.argument('input', nargs=-1)
def show(input):
    for fn in input:
        df = read_pcap_df(fn)
        result = analyse(df, os.path.split(fn)[1])
        pprint(result)

def read_pcap_df(filename):
    """
    Read PCAP and produce Pandas dataframe

    :return:
    """
    inputfile = open(filename)
    pcapfile = dpkt.pcap.Reader(inputfile)
    data = []
    for ts, buf in pcapfile:
        eth = dpkt.ethernet.Ethernet(buf)

        # FILTERING ONLY FOR IPv4 instead of packets ARP or IPv6
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data  # Loading the content of the ethernet into a variable 'ip'

            timestamp = ts  # 1
            ip_ttl = ip.ttl  # 2

            ip_proto = ip.p  # 3
            sport = ""
            dport = ""
            tcp_flag = ""
            http_request_method = ""
            if not (ip_proto == 6 or ip_proto == 17):  # It is not TCP or UDP
                continue

            ip_length = ip.len  # 4
            ip_src = socket.inet_ntoa(ip.src)  # 5
            ip_dst = socket.inet_ntoa(ip.dst)  # 6

            try:
                proto = ip.data  # Loading the content of the 'ip' into a variable 'protocol' that can be for example ICMP, TCP, and UDP.
            except:
                continue
            if isinstance(proto, str):
                continue
            sport = proto.sport  # 7
            dport = proto.dport  # 8

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
                    print
                    "EXCEPTION TCP FLAG" if debug else next

                if (proto.dport == 80) or (proto.dport == 443):
                    if proto.data == '':
                        http_request_method = ''
                    else:
                        try:
                            http_request_method = dpkt.http.Request(proto.data).method
                        except:
                            http_request_method = ''

            fragments = 1 if (
            int(ip.off & dpkt.ip.IP_MF) != 0) else 0  # 8 This flag is set to a 1 for all fragments except the last one


            data.append((ip_ttl, ip_proto, ip_length, ip_src, ip_dst, sport, dport, tcp_flag, fragments, http_request_method, len(buf)))


    columns = [
        'timestamp',
        'ip_ttl',
        'ip_proto',
        'ip_length',
        'ip_src',
        'ip_dst',
        'sport',
        'dport',
        'tcp_flag',
        'fragments',
        'http_data',
        'raw_size']
    return pd.DataFrame(data, columns=columns)

######
#Extra Functions (for enrichment purpose)
df_port_name = pd.read_csv('enrichments/port_name.txt',delimiter=",", names=['port_num','port_name'])
df_ip_proto_name = pd.read_csv('enrichments/ip_proto_name.txt',delimiter=",", names=['proto_num','proto_name'])

def get_ip_proto_name(ip_proto_number):
    try:
        return df_ip_proto_name[df_ip_proto_name['proto_num']==ip_proto_number]['proto_name'].values[0]
    except:
        return str(ip_proto_number)

def get_port_name(port_number):
    try:
        return df_port_name[df_port_name['port_num']==port_number]['port_name'].values[0]+" service port"
    except:
        return "port "+str(int(port_number))

def get_tcp_flag_name(tcp_flags_str):
    tcp_flags=""
    try:
        tcp_flags += ("FIN" if (tcp_flags_str.find('F') != -1) else next)
    except:
        next
    try:
        tcp_flags += ("SYN" if (tcp_flags_str.find('S')!= -1) else next)
    except:
        next

    try:
        tcp_flags += ("RST" if tcp_flags_str.find('R') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("PUSH" if tcp_flags_str.find('P') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("ACK" if tcp_flags_str.find('A') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("URG" if tcp_flags_str.find('U') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("ECE" if tcp_flags_str.find('E') != -1 else next)
    except:
        next

    try:
        tcp_flags += ("CWR" if tcp_flags_str.find('C') != -1 else next)
    except:
        next


    return tcp_flags

def analyse(df, name):
    """
    Analysis only top traffic stream

    :param df:
    :return:
    """
    debug = True
    attack_case = "-1"
    ttl_variation_threshold = 4



    result = {
        "reflected":False,
        "spoofed":False,
        "fragmented":False,
        "pattern_traffic_share":0.0,
        "pattern_packet_count":0,
        "pattern_total_megabytes":0,
        "start_timestamp":0,
        "end_timestamp":0,
        "dst_ports":[], #(port,share)
        "src_ports":[], #(port,share)
        "ttl_variation":[],
        "src_ips":[],
        "dst_ips":[],
        "packets":[]
    }    

    if debug: print("\n\n\n")
    top_ip_dst = df['ip_dst'].value_counts().index[0]
    if debug: print("Top dst IP: "+ top_ip_dst)
    result["dst_ips"] = top_ip_dst
    top_ip_proto = df[df['ip_dst'] == top_ip_dst]['ip_proto'].value_counts().index[0]
    if debug: print("Top IP protocol: "+str(top_ip_proto))

    ####
    # Performing a first filter based on the top_ip_dst (target IP), the source IPs canNOT be from the \16 of the
    # target IP, and the top IP protocol that targeted the top_ip_dst
    df_filtered = df[
        (df['ip_dst'] == top_ip_dst) & ~df['ip_src'].str.contains(".".join(top_ip_dst.split('.')[0:2]), na=False) & (
        df['ip_proto'] == top_ip_proto)]

    ####
    # Calculating the number of packets after the first filter 
    total_packets_filtered = len(df_filtered)
    if debug: print("Number of packets: "+str(total_packets_filtered))
    result["total_nr_packets"] = total_packets_filtered

    ####
    # For attacks in the IP protocol level
    attack_label = get_ip_proto_name(top_ip_proto) + "-based attack"
    result["transport_protocol"] = get_ip_proto_name(top_ip_proto)

    ####
    # For attacks based on TCP or UDP, which have source and destination ports
    if ((top_ip_proto == 6) or (top_ip_proto == 17)):

        if debug: print("\n####################\nREMAINING :\n####################")
        ####
        # Calculating the distribution of source ports based on the first filter
        percent_src_ports = df_filtered['sport'].value_counts().divide(float(total_packets_filtered) / 100)

        if debug: print("\nSource ports frequency")
        if debug: print(percent_src_ports.head())

        ####
        # Calculating the distribution of destination ports after the first filter
        percent_dst_ports = df_filtered['dport'].value_counts().divide(float(total_packets_filtered) / 100)
        if debug: print("\nDestination ports frequency")
        if debug: print(percent_dst_ports.head())

        #####
        ## WARNING packets are filtered here again#####
        # Using the top 1 (source or destination) port to analyse a pattern of packets
        if (len(percent_src_ports) > 0) and (len(percent_dst_ports) > 0):
            if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                if debug: print('Using top source port: ', percent_src_ports.keys()[0])
                df_pattern = df_filtered[df_filtered['sport'] == percent_src_ports.keys()[0]]
                result["selected_port"] = "src_" + str(percent_src_ports.keys()[0])
            else:
                if debug: print('Using top dest port: ', percent_dst_ports.keys()[0])
                df_pattern = df_filtered[df_filtered['dport'] == percent_dst_ports.keys()[0]]
                result["selected_port"] = "dst_" + str(percent_dst_ports.keys()[0])
        else:
            if debug: print('no top source/dest port')
            return None

        if debug: print("\n####################\nPATTERN "+ "\n####################")

        #####
        # Calculating the total number of packets involved in the attack
        pattern_packets = len(df_pattern)
        result["pattern_packet_count"] = pattern_packets

        #WARNING Can be wrong
        result['raw_attack_size_megabytes'] = df_pattern['raw_size'].sum() /1000000
        result["pattern_total_megabytes"] = df_pattern[df_pattern['fragments'] == 0]['ip_length'].sum() / 1000000

        #####
        # Calculating the percentage of the current pattern compared to the raw input file
        representativeness = float(pattern_packets) * 100 / float(total_packets_filtered)
        result["pattern_traffic_share"] = representativeness
        attack_label = 'In %.2f' % representativeness + "\n " + attack_label

        #####
        # Checking the existence of HTTP data
        http_data = df_pattern['http_data'].value_counts().divide(float(pattern_packets) / 100)

        #####
        # Checking the existence of TCP flags
        percent_tcp_flags = df_pattern['tcp_flag'].value_counts().divide(float(pattern_packets) / 100)

        #####
        # Calculating the number of source IPs involved in the attack
        ips_involved = df_pattern['ip_src'].unique()
        attack_label = attack_label + "\n"+ str(len(ips_involved)) + " source IPs"
        result["src_ips"] = ips_involved
        
        #####
        # Calculating the number of source IPs involved in the attack
        result["start_timestamp"] = df_pattern['timestamp'].min()
        result["end_timestamp"] = df_pattern['timestamp'].max()

        ####
        # Calculating the distribution of TTL variation (variation -> number of IPs)
        ttl_variations = df_pattern.groupby(['ip_src'])['ip_ttl'].agg(np.ptp).value_counts().sort_index()
        if debug: print('TTL variation : NR of source IPs')
        if debug: print(ttl_variations)
        result["ttl_variation"] = ttl_variations.to_dict()

        ####
        # Calculating the distribution of IP fragments (fragmented -> percentage of packets)
        percent_fragments = df_pattern['fragments'].value_counts().divide(float(pattern_packets) / 100)

        ####
        # Calculating the distribution of source ports that remains
        percent_src_ports = df_pattern['sport'].value_counts().divide(float(pattern_packets) / 100)
        if debug: print("\nSource ports frequency")
        if debug: print(percent_src_ports.head())
        result["src_ports"] = percent_src_ports.to_dict()

        ####
        # Calculating the distribution of destination ports after the first filter
        percent_dst_ports = df_pattern['dport'].value_counts().divide(float(pattern_packets) / 100)
        if debug: print("\nDestination ports frequency")
        if debug: print(percent_dst_ports.head())
        result["dst_ports"] = percent_dst_ports.to_dict()

        ####
        # There are 3 possibilities of attacks cases!
        if (percent_src_ports.values[0] == 100):
            if (len(percent_dst_ports) == 1):
                # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                attack_label = attack_label + "; using " + get_port_name(
                    percent_src_ports.keys()[0]) + "; to target " + get_port_name(
                    percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
            else:
                # if debug: print("\nCASE 2: 1 source port to a set of destination ports") if debug else next
                if (percent_dst_ports.values[0] >= 50):
                    attack_label = attack_label + "; using " + get_port_name(
                        percent_src_ports.keys()[0]) + "; to target a set of (" + str(
                        len(percent_dst_ports)) + ") ports, such as " + get_port_name(
                        percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                        0] + "%]" + " and " + get_port_name(percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                                 percent_dst_ports.values[
                                                                                                     1] + "%]"
                elif (percent_dst_ports.values[0] >= 33):
                    attack_label = attack_label + "; using " + get_port_name(
                        percent_src_ports.keys()[0]) + "; to target a set of (" + str(
                        len(percent_dst_ports)) + ") ports, such as " + get_port_name(
                        percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                        0] + "%]" + "; " + get_port_name(percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                              percent_dst_ports.values[
                                                                                                  1] + "%], and " + get_port_name(
                        percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
                else:
                    attack_label = attack_label + "; using " + get_port_name(
                        percent_src_ports.keys()[0]) + "; to target a set of (" + str(
                        len(percent_dst_ports)) + ") ports, such as " + get_port_name(
                        percent_dst_ports.keys()[0]) + "[" + '%.2f' % percent_dst_ports.values[
                        0] + "%]" + "; " + get_port_name(percent_dst_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                              percent_dst_ports.values[
                                                                                                  1] + "%], and " + get_port_name(
                        percent_dst_ports.keys()[2]) + "[" + '%.2f' % percent_dst_ports.values[2] + "%]"
        else:
            if (len(percent_src_ports) == 1):
                # if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                attack_label = attack_label + "; using " + get_port_name(percent_src_ports.keys()[0]) + "[" + '%.1f' % \
                                                                                                              percent_src_ports.values[
                                                                                                                  0] + "%]" + "; to target " + get_port_name(
                    percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"

            else:
                # if debug: print("\nCASE 3: 1 source port to a set of destination ports") if debug else next
                if (percent_src_ports.values[0] >= 50):
                    attack_label = attack_label + "; using a set of (" + str(
                        len(percent_src_ports)) + ") ports, such as " + get_port_name(
                        percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                        0] + "%] and " + get_port_name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                            percent_src_ports.values[
                                                                                                1] + "%]" + "; to target " + get_port_name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"
                elif (percent_src_ports.values[0] >= 33):
                    attack_label = attack_label + "; using a set of (" + str(
                        len(percent_src_ports)) + ") ports, such as " + get_port_name(
                        percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                        0] + "%], " + get_port_name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                         percent_src_ports.values[
                                                                                             1] + "%], and " + get_port_name(
                        percent_src_ports.keys()[2]) + "[" + '%.2f' % percent_src_ports.values[
                        2] + "%]" + "; to target " + get_port_name(percent_dst_ports.keys()[0]) + "[" + '%.1f' % \
                                                                                                        percent_dst_ports.values[
                                                                                                            0] + "%]"
                else:
                    attack_label = attack_label + "; using a set of (" + str(
                        len(percent_src_ports)) + ") ports, such as " + get_port_name(
                        percent_src_ports.keys()[0]) + "[" + '%.2f' % percent_src_ports.values[
                        0] + "%], " + get_port_name(percent_src_ports.keys()[1]) + "[" + '%.2f' % \
                                                                                         percent_src_ports.values[
                                                                                             1] + "%], " + get_port_name(
                        percent_src_ports.keys()[2]) + "[" + '%.2f' % percent_src_ports.values[
                        2] + "%]" + "; and " + get_port_name(percent_src_ports.keys()[3]) + "[" + '%.2f' % \
                                                                                                  percent_src_ports.values[
                                                                                                      3] + "%]" + "; to target " + get_port_name(
                        percent_dst_ports.keys()[0]) + "[" + '%.1f' % percent_dst_ports.values[0] + "%]"

        ####
        # Testing HTTP request
        if len(http_data) > 0 and ((percent_dst_ports.index[0] == 80) or (percent_dst_ports.index[0] == 443)):
            attack_label = attack_label + "; " + http_data.index[0]

        ####
        # Testing TCP flags
        if (len(percent_tcp_flags) > 0) and (percent_tcp_flags.values[0] > 50):
            attack_label = attack_label + "; TCP flags: " + get_tcp_flag_name(
                percent_tcp_flags.index[0]) + "[" + '%.1f' % percent_tcp_flags.values[0] + "%]"

        ####
        # IP fragmentation
        if (percent_fragments.values[0] > 0) and (percent_fragments.index[0] == 1):
            attack_label = attack_label + "; involving IP fragmentation"
            result["fragmented"] = True

        ####
        # IP spoofing (if (more than 0) src IPs had the variation of the ttl higher than a treshold)
        if (ttl_variations[::-1].values[0] > 0) and (ttl_variations[::-1].index[0] >= ttl_variation_threshold):
            result["spoofed"]=True
            attack_label = attack_label + "; (likely involving) spoofed IPs"
        else:
            ####
            # Reflection and Amplification
            if percent_src_ports.values[0] >= 1:
                result["reflected"]=True
                attack_label = attack_label + "; Reflection & Amplification"

        if debug: print("\n####################\nATTACK VECTOR LABEL:"+ "\n####################")
        if debug: print(attack_label)

        result["label"] = attack_label
        print(result)


    return result
   


if __name__ == "__main__":
    cli.add_command(search)
    cli.add_command(show)
    cli()