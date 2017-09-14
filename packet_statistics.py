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

@click.command()
def create_index():
    es = Elasticsearch()

    packet = {
        'ip_src': '10.0.0.1',
        'ip_dst': '10.0.0.2',
        'timestamp': datetime.utcnow(),
    }
    #creates index and adds data :/
    res = es.create(index='packets', id=packet['timestamp'].timestamp(), doc_type='packet', body=packet_fields, refresh=True)
    print(res)
    res = es.search(index="packets", body={"query": {"match": {'ip_src':'10.0.0.1'}}})
    print(res)

@click.command()
def count():
    es = Elasticsearch()
    print(es.indices.refresh(index='packets4'))
    count = es.count(index='packets4', doc_type='packet4', body={"query": {"match_all": {}}})
    print(count)
    count = es.search(index='packets4', doc_type='packet4', body={"query": {"match_all": {}}})
    print(count)

@click.command()
def stream():
    es = Elasticsearch()
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
                ts = payload['timestamp']
                payload['timestamp'] = datetime.fromtimestamp(ts)
                #print(d)
                try:
                    res = es.create(index='packets4', doc_type='packet4', id=ts, body=payload)
                except ConflictError as e:
                    print('Conclict Error')


                if not res['created']:
                    print('ERROR adding to index')
    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass

if __name__ ==  "__main__":
    cli.add_command(create_index)
    cli.add_command(stream)
    cli.add_command(count)
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




