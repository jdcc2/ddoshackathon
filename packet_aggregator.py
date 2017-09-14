import redis
import msgpack
import dpkt
import multiprocessing
import time
import click
import pandas as pd

from ddos_labeling_jh import analyse

@click.group()
def cli():
    pass

@click.command()
def run():
    aggregate(interval=300)

@click.command()
@click.option('--host', default='localhost')
@click.option('--port', default=6379)
def print_packets(host, port):
    r = redis.StrictRedis(host=host, port=port, db=0)
    p = r.pubsub()
    p.subscribe('packets')
    try:
        # non-blocking
        # while True:
        #     print(p.get_message())

        # blocking
        start_interval = time.time()
        for message in p.listen():
            if isinstance(message['data'], bytes):
                payload = msgpack.unpackb(message['data'], encoding='utf-8')
                print(payload)
    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass
@click.command()
@click.option('--interval', default=300)
@click.option('--packets', default=5000)
@click.option('--host', default='localhost')
@click.option('--port', default=6379)
def aggregate(interval=300, packets=5000, host='localhost', port=6379):
    r = redis.StrictRedis(host=host, port=port, db=0)
    p = r.pubsub()
    p.subscribe('packets')

    packet_fields = {
        'timestamp': 0,  # date
        'ip_src': '',
        'ip_dst': '',
        'ip_proto': 0,
        'ip_length': 0,
        'sport': 0,
        'dport': 0,
        'tcp_flag': '',
        'http_data': '',
        'fragments': 0
    }

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
        ]
    try:
        # non-blocking
        # while True:
        #     print(p.get_message())

        # blocking
        start_interval = time.time()
        current_data = []
        packet_counter = 0
        for message in p.listen():
            if isinstance(message['data'], bytes):
                payload = msgpack.unpackb(message['data'], encoding='utf-8')
                payload = packet_fields.update(payload)
                current_data.append((
                    payload['timestamp'], payload['ip_ttl'],
                    payload['ip_proto'], payload['ip_length'],
                    payload['ip_src'], payload['ip_dst'],
                    payload['sport'], payload['dport'],
                    payload['tcp_flag'], payload['fragments'],
                    payload['http_data'],
                    ))
                packet_counter += 1
            if packet_counter >= packets or time.time() - start_interval >interval:
                # new set
                analyse(pd.DataFrame(current_data, columns=columns), 'test')
                packet_counter = 0
                start_interval= time.time()
                current_data = []

    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass



if __name__ ==  "__main__":
    cli.add_command(print_packets)
    cli.add_command(aggregate)
    cli()






