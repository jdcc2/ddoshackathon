import redis
import msgpack
import dpkt
from datetime import datetime
import click
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConflictError

packet_fields = {
    'timestamp' : 0, #date
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

@click.group()
def cli():
    pass

@click.option('--host', default='localhost')
@click.option('--port', default=6379)
@click.command()
def run(host, port):
    r = redis.StrictRedis(host='localhost', port=6379, db=0)
    p = r.pubsub()
    p.subscribe('packets')
    try:
        #non-blocking
        # while True:
        #     print(p.get_message())

        #blocking
        for message in p.listen():
            if isinstance(message['data'], bytes):
                payload = msgpack.unpackb(message['data'], encoding='utf-8')
                print(payload)
    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass

if __name__ ==  "__main__":
    cli.add_command(run)
    cli()

    # res = es.index(index="packets", doc_type='packets', id=1, body=doc)
    # print(res['created']
    #
    # res = es.get(index="test-index", doc_type='tweet', id=1)
    # print(res['_source'])
    #
    # es.indices.refresh(index="test-index")
    #
    # res = es.search(index="test-index", body={"query": {"match_all": {}}})
    # print("Got %d Hits:" % res['hits']['total'])
    # for hit in res['hits']['hits']:
    #     print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])
    #
    # r = redis.StrictRedis(host='localhost', port=6379, db=0)
    # p = r.pubsub()
    # p.subscribe('packets')
    # try:
    #     #non-blocking
    #     # while True:
    #     #     print(p.get_message())
    #
    #     #blocking
    #     for message in p.listen():
    #         if isinstance(message['data'], bytes):
    #             payload = msgpack.unpackb(message['data'])
    #             print(payload)
    # except KeyboardInterrupt as e:
    #     print("Keyboard interrupt")
    #     pass




