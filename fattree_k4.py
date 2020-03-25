#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
from mininet.util import dumpNodeConnections
import logging
import os 

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger( __name__ )

class FatTree(Topo):
    logger.debug("Class FatTree")
    CoreSwitchList = []
    AggSwitchList = []
    EdgeSwitchList = []
    HostList = []
    _num = 0
    def __init__(self):
        logger.debug("Class FatTree init")
        _num = 4

        self._num = _num
        self._coreLayer = _num
        self._aggLayer = _num * _num / 2
        self._edgeLayer = self._aggLayer
        self._host = self._edgeLayer * _num / 2


        #Init Topo
        Topo.__init__(self)

        logger.debug("Start create Core Layer Swich")
        self.createCoreLayerSwitch(self._coreLayer)
        logger.debug("Start create Agg Layer Swich ")
        self.createAggLayerSwitch(self._aggLayer)
        logger.debug("Start create Edge Layer Swich ")
        self.createEdgeLayerSwitch(self._edgeLayer)
        logger.debug("Start create Host")
        self.createHost(self._host)

        self.createLink()
    """
    Create Switch and Host
    """

    def createCoreLayerSwitch(self, NUMBER):
        logger.debug("Create Core Layer")
        for x in range(1, NUMBER+1):
            PREFIX = "C_00"
            if x >= int(10):
                PREFIX = "C_0"
            self.CoreSwitchList.append(self.addSwitch(PREFIX + str(x)))

    def createAggLayerSwitch(self, NUMBER):
        logger.debug( "Create Agg Layer")
        for x in range(1, NUMBER+1):
            PREFIX = "A_00"
            if x >= int(10):
                PREFIX = "A_0"
            self.AggSwitchList.append(self.addSwitch(PREFIX + str(x)))

    def createEdgeLayerSwitch(self, NUMBER):
        logger.debug("Create Edge Layer")
        for x in range(1, NUMBER+1):
            PREFIX = "E_00"
            if x >= int(10):
                PREFIX = "E_0"
            self.EdgeSwitchList.append(self.addSwitch(PREFIX + str(x)))

    def createHost(self, NUMBER):
        logger.debug("Create Host")
        for x in range(1, NUMBER+1):
            PREFIX = "H_00"
            if x >= int(10):
                PREFIX = "H_0"
            self.HostList.append(self.addHost(PREFIX + str(x))) 

    """
    Create Link 
    """
    def createLink(self):
        logger.debug("Create Core to Agg")
        #for x in range(0, self._coreLayer):
        #    for y in range(x%2,self._aggLayer,self._coreLayer/2):
        #        self.addLink(self.AggSwitchList[y], self.CoreSwitchList[x])
        for x in range(0, self._aggLayer, 2):
            self.addLink(self.CoreSwitchList[0], self.AggSwitchList[x])
            self.addLink(self.CoreSwitchList[1], self.AggSwitchList[x])
        for x in range(1, self._aggLayer, 2):
            self.addLink(self.CoreSwitchList[2], self.AggSwitchList[x])
            self.addLink(self.CoreSwitchList[3], self.AggSwitchList[x])

        logger.debug("Create Agg to Edge")
        for x in range(0, self._aggLayer, 2):
         #    for y in range(x, x+2):
         #       for z in range(x, x+2):
         #           self.addLink(self.AggSwitchList[y], self.EdgeSwitchList[z])
            self.addLink(self.AggSwitchList[x], self.EdgeSwitchList[x])
            self.addLink(self.AggSwitchList[x], self.EdgeSwitchList[x+1])
            self.addLink(self.AggSwitchList[x+1], self.EdgeSwitchList[x])
            self.addLink(self.AggSwitchList[x+1], self.EdgeSwitchList[x+1])

        logger.debug("Create Edge to Host")
        for x in range(0, self._edgeLayer):
            ## limit = 2 * x + 1 
            self.addLink(self.EdgeSwitchList[x], self.HostList[2 * x])
            self.addLink(self.EdgeSwitchList[x], self.HostList[2 * x + 1])


topos = { 'fattree': ( lambda: FatTree() ) }
