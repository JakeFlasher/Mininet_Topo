#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
from mininet.util import dumpNodeConnections


class Fattree(Topo):
    CoreSwitchList = []
    AggSwitchList = []
    EdgeSwitchList = []
    HostList = []

    def __init__(self, k=4, density=2):
        self._pod = k
        self._CoreLayer = (k/2)**2
        self._AggLayer = k*k/2
        self._EdgeLayer = k*k/2
        self._density = density
        self._Host = self._EdgeLayer * density
        #Init Topo
        Topo.__init__(self)
    	self.createTopo()
    	self.createLink()

    def createTopo(self):
        self.createCoreLayer(self._CoreLayer)
        self.createAggLayer(self._AggLayer)
        self.createEdgeLayer(self._EdgeLayer)
        self.createHost(self._Host)
    """
    Create Switch and Host
    """
    def _addSwitch(self, num, level, switch_list):
        for x in xrange(1, num+1):
            switch_list.append(self.addSwitch(level + str(x)))

    def createCoreLayer(self, num):
        self._addSwitch(num, 'c', self.CoreSwitchList)

    def createAggLayer(self, num):
        self._addSwitch(num, 'a', self.AggSwitchList)

    def createEdgeLayer(self, num):
        self._addSwitch(num, 'e', self.EdgeSwitchList)

    def createHost(self, num):
        for x in xrange(1, num+1):
            self.HostList.append(self.addHost('h' + str(x)))
    """
    Add Link
    """
    def createLink(self):
	for x in xrange(0, self._CoreLayer):
            for y in xrange(x%(self._pod/2), self._AggLayer, self._pod/2):
                self.addLink(self.CoreSwitchList[x],self.AggSwitchList[y])

        for x in xrange(0, self._AggLayer, self._pod/2):
            for i in xrange(0, self._pod/2):
                for j in xrange(0, self._pod/2):
                    self.addLink(self.AggSwitchList[x+i], self.EdgeSwitchList[x+j])

        for x in xrange(0, self._EdgeLayer):
            for i in xrange(0, self._density):
                self.addLink(self.EdgeSwitchList[x],self.HostList[self._density * x + i])

topos = { 'fattree': ( lambda: Fattree() ) }

def simpleTest():
    topo = Fattree()
    net = Mininet(topo. controller=RemoteControlloer,host=CPU
