#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

#self.addLink( node1, node2, bw=10, delay='5ms', max_queue_size=1000, loss=10, use_htb=True): adds a bidirectional link with bandwidth, delay and loss characteristics, with a maximum queue size of 1000 packets using the Hierarchical Token Bucket rate limiter and netem delay/loss emulator. The parameter bw is expressed as a number in Mbit; delay is expressed as a string with units in place (e.g. '5ms', '100us', '1s'); loss is expressed as a percentage (between 0 and 100); and max_queue_size is expressed in packets.
#self.addHost(name, cpu=f):This allows you to specify a fraction of overall system CPU resources which will be allocated to the virtual host.

class SingSwitch(Topo):
    
    def __init__(self, n=2, **opts)
        
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1')
        for i in range(n):
            host = self.addHost('h%s' % str(i+1), cpu=.5/n)
            self.addLink(host, switch, bw=10, delay='5ms', loss=2, max_queue_size=1000, use_htb=True)

def perfTest():
    
    n=4
    topo = SingleSwitch(n=n)
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Testing network connectivity")
    net.pingAll()
    print("Testing bandwidth amongst the hosts h1-h%s" % str(n))
    h1, h4 = net.get('h1', 'h4')
    net.iperf((h1,h4))
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    perfTest()


