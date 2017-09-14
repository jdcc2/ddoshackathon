import redis
import msgpack
import dpkt

if __name__ ==  "__main__":
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    p = r.pubsub()
    p.subscribe('test')
    try:
        #non-blocking
        # while True:
        #     print(p.get_message())

        #blocking
        for message in p.listen():
            if isinstance(message['data'], bytes):
                payload = msgpack.unpackb(message['data'])
                print(payload)
    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass




