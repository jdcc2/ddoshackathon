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






