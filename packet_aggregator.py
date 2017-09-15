import redis
import msgpack
import multiprocessing as mp
import time
import click
import pandas as pd

from packet_patterns import analyse

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
@click.option('--time_limit', default=300)
@click.option('--packets', default=-1, help='the maximum number of packets to aggregate before starting analysis, set to -1 to ignore packet limit, defaults to -1')
@click.option('--host', default='localhost')
@click.option('--port', default=6379)
def aggregate(interval=300, time_limit=300, packets=5000, host='localhost', port=6379):
    pool = mp.Pool()
    worker_results = []
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
        'fragments': 0,
        'raw_size': 0
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
        'raw_size'
        ]
    try:
        # non-blocking
        # while True:
        #     print(p.get_message())

        # blocking
        start_window = time.time()
        start_timestamp = None
        current_data = []
        packet_counter = 0
        print("starting loop")
        for message in p.listen():
            if isinstance(message['data'], bytes):
                p = msgpack.unpackb(message['data'], encoding='utf-8')
                if start_timestamp is None:
                    start_timestamp = p['timestamp']
                payload = {}
                payload.update(packet_fields)
                payload.update(p)

                current_data.append((
                    payload['timestamp'], payload['ip_ttl'],
                    payload['ip_proto'], payload['ip_length'],
                    payload['ip_src'], payload['ip_dst'],
                    payload['sport'], payload['dport'],
                    payload['tcp_flag'], payload['fragments'],
                    payload['http_data'], payload['raw_size']
                    ))
                packet_counter += 1
                if (packets != -1 and packet_counter >= packets) \
                    or (time_limit != 1 and time.time() - start_window >= time_limit)\
                    or (payload['timestamp'] - start_timestamp >= interval):

                    # new set
                    reason = ''
                    if packet_counter == packets:
                        reason = 'packet limit of {} packets hit'.format(packets)
                    elif payload['timestamp'] - start_timestamp >= interval:
                        reason = 'interval of {} seconds exceeded'.format(interval)
                    else:
                        reason = 'time limit of {} seconds reached'.format(time_limit)


                    #p = mp.Process(target=analyse, args=(pd.DataFrame(current_data, columns=columns), 'test'))
                    #p.start()
                    print('Running job results')
                    for w in worker_results:
                        print(type(w))
                        #print(w.ready())
                        print(w)
                    print("Starting analyze worker, {}".format(reason))
                    worker_results.append(pool.apply(analyse_worker, [pd.DataFrame(current_data, columns=columns), host, port]))

                    packet_counter = 0
                    start_window = time.time()
                    start_timestamp = p['timestamp']
                    current_data = []

    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pool.terminate()
        pass

def analyse_worker(d, host, port):
    try:
        r = redis.StrictRedis(host=host, port=port, db=0)
        p = r.pubsub()
        print('Worker started')
        print(d[0:1]['timestamp'][0])
        res = analyse(d)
        print('Worker result')
        print(res)
        for k in res.keys():
            print(k, type(res[k]))
            if isinstance(res[k], dict):
                for l in res[k].keys():
                    print(l, type(res[k][l]))

        r.publish('patterns', msgpack.packb(res, use_bin_type=False))
    except KeyboardInterrupt as e:
        print('Worker received keyboard interrupt')

if __name__ ==  "__main__":
    cli.add_command(print_packets)
    cli.add_command(aggregate)
    cli()






