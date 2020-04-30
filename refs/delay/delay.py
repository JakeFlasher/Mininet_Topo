import logging
import struct
import copy
import networkx as nx
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib import hub
from ryu.base.app_manager import lookup_service_brick
import time

from collections import defaultdict
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link, get_switch, get_link
import setting
from ryu.topology.switches import LLDPPacket
from ryu.topology.switches import Switches


class NetworkAwareness(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args):
        super(NetworkAwareness, self).__init__(*args)
        self.dpid_mac_port = {}
        self.net = nx.DiGraph()
        self.topology_api_app = self
        self.name = "awareness"
        self.link_to_port = {}  # (src_dpid,dst_dpid)->(src_port,dst_port)
        self.access_table = {}  # {(sw,port) :[host1_ip]}
        self.switch_port_table = {}  # dpip->port_num
        self.access_ports = defaultdict(dict)  # dpid->port_num
        self.interior_ports = {}  # dpid->port_num

        self.graph = nx.DiGraph()
        self.pre_graph = nx.DiGraph()
        self.pre_access_table = {}
        self.pre_link_to_port = {}
        self.shortest_paths = None
        self.datapaths = {}
        self.arp_num = 0
        self.n = 0
        self.delay = defaultdict(dict)
        self.lldpdelay = defaultdict(dict)
        self.echo_latency = defaultdict(float)

        self.switches_object = None

        self.discover_thread = hub.spawn(self._discover)

    # self.detect_thread = hub.spawn(self._detector)

    def _discover(self):
        i = 0
        while True:
            self._detector()
            self.get_topology(None)
            self.show_topology()
            hub.sleep(2)

    def show_topology(self):
        return

    def _detector(self):
        self.create_link_delay()
        self.shortest_paths = {}
        # print "Refresh the shortest_paths"

        # self.show_delay_statis()
        # self._send_echo_request()
        # hub.sleep(setting.DELAY_DETECTING_PERIOD)

    def show_delay_statis(self):
        print
        self.graph.edges()
        if setting.TOSHOW:
            # print "\nsrc   dst      delay"
            # ssprint "---------------------------"
            for src in self.graph:
                for dst in self.graph[src]:
                    if (src, dst) in self.graph.edges():
                        print
                        self.delay[src][dst]
                    """print "src="
                    print src 
                    print dst
                    print "delay = "
                    print delay"""
                    # self.logger.info("%s<-->%s : %s" % (src, dst, delay))

    def _send_echo_request(self):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            data = "%.6f" % time.time()
            echo_req = parser.OFPEchoRequest(datapath, data=data)
            datapath.send_msg(echo_req)

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        latency = time.time() - eval(ev.msg.data)
        self.echo_latency[ev.msg.datapath.id] = latency

    def get_dalay(self, src, dst):
        try:
            fwd_delay = self.lldpdelay[src][dst]
            re_delay = self.lldpdelay[dst][src]
            src_latency = self.echo_latency[src]
            dst_latency = self.echo_latency[dst]
            """print "data"
            print fwd_delay
            print re_delay
            print src_latency
            print dst_latency"""

            delay = (fwd_delay + re_delay - src_latency - dst_latency) / 2
            return max(delay, 0)
        except:
            return float('inf')

    def create_link_delay(self):
        # print "create link delay"
        try:
            for src in self.graph:
                for dst in self.graph[src]:
                    if src == dst:
                        self.delay[src][dst] = 0
                        continue
                    delay = self.get_dalay(src, dst)
                    self.delay[src][dst] = delay
        except:
            return
        return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        # self.logger.info("switch:%s connected", datapath.id)

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def get_host_location(self, host_ip):
        for key in self.access_table.keys():
            if self.access_table[key][0] == host_ip:
                return key
        self.logger.info("%s location is not found." % host_ip)
        return None

    def get_switches(self):
        return self.switches

    events = [event.EventSwitchEnter,
              event.EventSwitchLeave, event.EventPortAdd,
              event.EventPortDelete, event.EventPortModify,
              event.EventLinkAdd, event.EventLinkDelete]

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def get_weight(self, links):
        for link in links:
            src = link.src
            dst = link.dst
            delay = self.get_dalay(src.dpid, dst.dpid)
            if delay != float('inf'):
                self.graph.add_edge(src.dpid, dst.dpid, weight=delay)

    # @set_ev_cls(events)
    def get_topology(self, ev):
        # print "getto"
        switch_list = get_switch(self, None)
        self.create_port_map(switch_list)
        self.switches = self.switch_port_table.keys()
        links = get_link(self, None)
        self.create_interior_links(links)
        self.create_access_ports()
        self.get_weight(links)
        # self.get_graph(self.link_to_port.keys())

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dpid in self.access_ports:
            for port in self.access_ports[dpid]:
                if (dpid, port) not in self.access_table.keys():
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)

    def arp_forwarding(self, msg, src_ip, dst_ip):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        result = self.get_host_location(dst_ip)
        if result:  # host record in access table.
            datapath_dst, out_port = result[0], result[1]

            datapath_1 = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath_1, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER,
                                         out_port, msg.data)
            datapath_1.send_msg(out)
        else:
            self.flood(msg)

    def get_sw(self, dpid, in_port, src, dst):
        src_sw = dpid
        dst_sw = None

        src_location = self.get_host_location(src)
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = src_location[0]
            else:
                return None

        dst_location = self.get_host_location(dst)
        if dst_location:
            dst_sw = dst_location[0]

        return src_sw, dst_sw

    def get_path(self, src, dst):
        self._detector()
        try:
            return nx.dijkstra_path(self.graph, src, dst)
        except:
            print
            "No path"
            return None

    def create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())
            for p in sw.ports:
                self.switch_port_table[dpid].add(p.port_no)

    # get links`srouce port to dst port  from link_list,
    # link_to_port:(src_dpid,dst_dpid)->(src_port,dst_port)
    def create_interior_links(self, link_list):
        for link in link_list:
            src = link.src
            dst = link.dst
            self.link_to_port[
                (src.dpid, dst.dpid)] = (src.port_no, dst.port_no)

            # find the access ports and interiorior ports
            if link.src.dpid in self.switches:
                self.interior_ports[link.src.dpid].add(link.src.port_no)
            if link.dst.dpid in self.switches:
                self.interior_ports[link.dst.dpid].add(link.dst.port_no)

    # get ports without link into access_ports
    def create_access_ports(self):
        for sw in self.switch_port_table:
            all_port_table = self.switch_port_table[sw]
            interior_port = self.interior_ports[sw]
            self.access_ports[sw] = all_port_table - interior_port

    def get_link_to_port(self, link_to_port, src_dpid, dst_dpid):
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("dpid:%s->dpid:%s is not in links" % (
                src_dpid, dst_dpid))
            return None

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))

        match = parser.OFPMatch(
            in_port=src_port, eth_type=flow_info[0],
            ipv4_src=flow_info[1], ipv4_dst=flow_info[2])

        self.add_flow(datapath, 1, match, actions,
                      idle_timeout=15, hard_timeout=60)

    def get_port(self, dst_ip, access_table):
        # access_table: {(sw,port) :(ip, mac)}
        if access_table:
            if isinstance(access_table.values()[0], tuple):
                for key in access_table.keys():
                    if dst_ip == access_table[key][0]:
                        dst_port = key[1]
                        return dst_port
        return None

    def register_access_info(self, dpid, in_port, ip, mac):
        if in_port in self.access_ports[dpid]:
            if (dpid, in_port) in self.access_table:
                if self.access_table[(dpid, in_port)] == (ip, mac):
                    return
                else:
                    self.access_table[(dpid, in_port)] = (ip, mac)
                    return
            else:
                self.access_table.setdefault((dpid, in_port), None)
                self.access_table[(dpid, in_port)] = (ip, mac)
                return

    def install_flow(self, datapaths, link_to_port, access_table, path,
                     flow_info, buffer_id, data=None):
        ''' path=[dpid1, dpid2...]
            flow_info=(eth_type, src_ip, dst_ip, in_port)
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = flow_info[3]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        back_info = (flow_info[0], flow_info[2], flow_info[1])
        # inter_link
        if len(path) > 2:
            for i in xrange(1, len(path) - 1):
                port = self.get_link_to_port(link_to_port, path[i - 1], path[i])
                port_next = self.get_link_to_port(link_to_port,
                                                  path[i], path[i + 1])
                if port and port_next:
                    src_port, dst_port = port[1], port_next[0]
                    datapath = datapaths[path[i]]
                    self.send_flow_mod(datapath, flow_info, src_port, dst_port)
                    self.send_flow_mod(datapath, back_info, dst_port, src_port)
                    self.logger.debug("inter_link flow install")
        if len(path) > 1:
            # the last flow entry: tor -> host
            port_pair = self.get_link_to_port(link_to_port, path[-2], path[-1])
            if port_pair is None:
                self.logger.info("Port is not found")
                return
            src_port = port_pair[1]

            dst_port = self.get_port(flow_info[2], access_table)
            if dst_port is None:
                self.logger.info("Last port is not found.")
                return

            last_dp = datapaths[path[-1]]
            self.send_flow_mod(last_dp, flow_info, src_port, dst_port)
            self.send_flow_mod(last_dp, back_info, dst_port, src_port)

            # the first flow entry
            port_pair = self.get_link_to_port(link_to_port, path[0], path[1])
            if port_pair is None:
                self.logger.info("Port not found in first hop.")
                return
            out_port = port_pair[0]
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

        # src and dst on the same datapath
        else:
            out_port = self.get_port(flow_info[2], access_table)
            if out_port is None:
                self.logger.info("Out_port is None in same dp")
                return
            self.send_flow_mod(first_dp, flow_info, in_port, out_port)
            self.send_flow_mod(first_dp, back_info, out_port, in_port)
            self.send_packet_out(first_dp, buffer_id, in_port, out_port, data)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        if result:
            src_sw, dst_sw = result[0], result[1]
            if dst_sw:
                path = self.get_path(src_sw, dst_sw)
                if path is None:
                    return
                print
                "printing path"
                self.logger.info("[PATH]%s<-->%s: %s" % (ip_src, ip_dst, path))
                self.print_total_delay2(path)
                flow_info = (eth_type, ip_src, ip_dst, in_port)
                self.install_flow(self.datapaths,
                                  self.link_to_port,
                                  self.access_table, path,
                                  flow_info, msg.buffer_id, msg.data)
        return

    def print_total_delay(self, path):
        l = len(path)
        re = 0.0
        if l > 1:
            i = 0
            while i + 1 < l:
                # print "path[i + 1]"
                # print path[i + 1]
                re = re + self.get_dalay(path[i], path[i + 1])
                re = re * 2;
                # print "delay"
                # print self.get_dalay(path[i], path[i + 1])
                i = i + 1
            re = re + self.echo_latency[-1] / 2
        re = re + self.echo_latency[0] / 2
        print
        "total delay ="
        print
        re

    def print_total_delay2(self, path):
        l = len(path)
        re = 0.0
        if l > 1:
            i = 0
            while i + 1 < l:
                # print "path[i + 1]"
                # print path[i + 1]
                re = re + self.graph.get_edge_data(path[i], path[i + 1])['weight']
                # print "delay"
                # print self.graph.get_edge_data(path[i], path[i + 1])['weight']
                i = i + 1
            re = re + self.echo_latency[path[-1]] / 2
            # print "echo -1"
            # print self.echo_latency[-1] / 2
            # re = re +  self.echo_latency[0] / 2
            # print "echo 0"
        re = re + self.echo_latency[path[0]] / 2
        self.logger.info("total delay = %d ms" % (re * 1000))

    def _packet_in_handler_2(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac

            # record the access info
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)

    def _lldp_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        src_dpid = None
        src_port_no = None
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)

        except:
            return
        if self.switches_object is None:
            self.switches_object = lookup_service_brick('switches')
        for port in self.switches_object.ports.keys():
            if src_dpid == port.dpid and src_port_no == port.port_no:
                self.lldpdelay[src_dpid][dpid] = self.switches_object.ports[port].delay

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self._lldp_handler(ev)
        self._packet_in_handler_2(ev)
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if isinstance(arp_pkt, arp.arp):
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if isinstance(ip_pkt, ipv4.ipv4):
            if len(pkt.get_protocols(ethernet.ethernet)):
                eth_type = pkt.get_protocols(ethernet.ethernet)[0].ethertype
                self.shortest_forwarding(msg, eth_type, ip_pkt.src, ip_pkt.dst)
