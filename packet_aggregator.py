import redis
import msgpack
import dpkt
import multiprocessing
import time
import click

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

def aggregate(interval=300):
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
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
            if time.time() - start_interval >interval:
                # new set
                label(dataframe)

    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass

if __name__ ==  "__main__":
    cli.add_command(print)
    cli.add_command(run)
    cli()






