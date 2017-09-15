import redis
import msgpack
from datetime import datetime
import ujson as json

if __name__ == "__main__":
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
                with open('{}_pattern.json'.format(str(datetime.now().timestamp())), 'w') as f:
                    json.dump(payload, f)
    except KeyboardInterrupt as e:
        print('Keyboard interrupt')
