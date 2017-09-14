import redis
import msgpack
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import random
import pandas as pd
import numpy as np
from datetime import datetime
import click
import random

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
fig = plt.figure()
ax = fig.add_subplot(211)
ax2 = fig.add_subplot(212)

xar = []
yar = []
pattern1x = []
pattern2x = []


#r1 = p.line([], [], color="firebrick", line_width=2)

@click.group()
def cli():
    pass

@click.option('--host', default='localhost')
@click.option('--port', default=6379)
@click.command()
def run(host, port):
    r = redis.StrictRedis(host=host, port=6379, db=0)
    p = r.pubsub()
    p.subscribe('packets')
    try:
        #non-blocking
        # while True:
        #     print(p.get_message())        
        portcomb = {}

        #blocking
        for message in p.listen():
            if isinstance(message['data'], bytes):
                payload = msgpack.unpackb(message['data'], encoding='utf-8')
                print(payload)

                # plot real-time normal series
                
                xar.append(payload['timestamp'])
                yar.append(int(payload['raw_size'] ))
                ax.clear()
                ax.plot(xar, yar, 'g-') 

                ax2.text(5,6,'Hi')
 
                if(payload['sport'] in portcomb):
                    if (payload['dport'] not in portcomb[payload['sport']]):
                        portcomb[payload['sport']].append(payload['dport'])
                        
                else:
                    portcomb[payload['sport']] = [payload['dport']]
          


                plt.pause(0.05)            
                plt.show(block=False)


    except KeyboardInterrupt as e:
        print("Keyboard interrupt")
        pass

if __name__ ==  "__main__":
    plt.ion()
    cli.add_command(run)
    cli()
