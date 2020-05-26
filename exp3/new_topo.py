#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController
from mininet.cli import CLI


class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."

    def build(self):
        s3 = self.addSwitch('s3')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s1, s4)
        self.addLink(s4, s5)
        self.addLink(s3, s5)
        self.addLink(h1, s1)
        self.addLink(h2, s5)


def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo()
    net = Mininet(topo=topo, controller=lambda name: RemoteController(name, ip='127.0.0.1'))
    net.start()
    CLI(net)
    # print "Dumping host connections"
    # dumpNodeConnections(net.hosts)
    # print "Testing network connectivity"
    # net.pingAll()
    # CLI(net)
    net.stop()


if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
