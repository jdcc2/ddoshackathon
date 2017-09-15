import redis
import msgpack
from datetime import datetime
import ujson as json
import click
import os


def cli():
    pass

@click.command()
@click.argument('destination')
def dump(destination):
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    p = r.pubsub()
    p.subscribe('patterns')
    try:
        # non-blocking
        # while True:
        #     print(p.get_message())

        # blocking
        for message in p.listen():
            if isinstance(message['data'], bytes):
                payload = msgpack.unpackb(message['data'], encoding='utf-8')
                if (payload["transport_protocol"] == "UDP" or payload["transport_protocol"] == "TCP")\
                    and payload["total_nr_packets"] > 1000:
                    print("writing pattern to file")
                    p = os.path.abspath(destination)
                    with open('{}/to_block.json'.format(p, str(datetime.now().timestamp())), 'w') as f:
                        json.dump(payload, f)
                        f.truncate()


    except KeyboardInterrupt as e:
        print('Keyboard interrupt')


if __name__ == "__main__":
    cli.add_command(dump)
    cli()
