from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.topology.api import get_link
from ryu.lib.packet import ether_types
from ryu.app.wsgi import  WSGIApplication
from collections import defaultdict
import network_monitor
from Node import Node
from ryu.ofproto.ofproto_v1_3_parser import OFPActionOutput
from ryu.ofproto.ofproto_v1_3_parser import OFPSwitchFeatures
import sys


class DynamicRules(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "Network_Monitor": network_monitor.Network_Monitor,
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(DynamicRules, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_mac = {}
        self.mac_to_dpid = {}  # {mac:(dpid,port)}

        self.datapaths = {}
        self.topology_api_app = self
        self.src_links = defaultdict(lambda: defaultdict(lambda: None))

        self.check_ip_dpid = defaultdict(list)

        self.qos_ip_bw_list = []

        self.network_monitor = kwargs["Network_Monitor"]


        self.ip_to_switch = {}
        self.port_name_to_num = {}

        self.ip_to_port = {}  #{ip:(dpid,port)}
        #promise me, use it well :)
        self.pathmod = 0
        self.path = None
        #self.count = defaultdict(lambda: None)
        self.count = {}
        self.entry = {}
        self.to_delete = []

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        cookie = datapath.id
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, cookie)

    def add_flow(self, datapath, priority, match, actions, cookie, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, cookie = cookie,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, cookie = cookie,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # in rest_topology, self.mac_to_port is for the find for host
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # arp handle
        if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)

            if pkt_arp.dst_ip in self.ip_to_mac:
                #self.logger.info("[PACKET] ARP packet_in.")
                self.handle_arpre(datapath=datapath, port=in_port,
                                  src_mac=self.ip_to_mac[pkt_arp.dst_ip],
                                  dst_mac=src, src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
            else:
                # to avoid flood when the dst ip not in the network
                if datapath.id not in self.check_ip_dpid[pkt_arp.dst_ip]:
                    self.check_ip_dpid[pkt_arp.dst_ip].append(datapath.id)
                    out_port = ofproto.OFPP_FLOOD
                    actions = [parser.OFPActionOutput(out_port)]
                    data = None
                    if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                        data = msg.data
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                              in_port=in_port, actions=actions, data=data)
                    datapath.send_msg(out)
            return

        elif pkt_arp and pkt_arp.opcode == arp.ARP_REPLY:
            if pkt_arp.src_ip not in self.ip_to_mac:
                self.ip_to_mac[pkt_arp.src_ip] = src
                self.mac_to_dpid[src] = (dpid, in_port)
                self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)
            dst_mac = self.ip_to_mac[pkt_arp.dst_ip]
            (dst_dpid, dst_port) = self.mac_to_dpid[dst_mac]
            self.handle_arpre(datapath=self.datapaths[dst_dpid], port=dst_port, src_mac=src, dst_mac=dst_mac,
                              src_ip=pkt_arp.src_ip, dst_ip=pkt_arp.dst_ip)
            return

        if pkt_ipv4 and (self.ip_to_port.get(pkt_ipv4.dst)) and (self.ip_to_port.get(pkt_ipv4.src)):
            (src_dpid, src_port) = self.ip_to_port[pkt_ipv4.src]  # src dpid and port
            (dst_dpid, dst_port) = self.ip_to_port[pkt_ipv4.dst]  # dst dpid and port
            self.install_path(src_dpid=src_dpid, dst_dpid=dst_dpid, src_port=src_port, dst_port=dst_port,
                              ev=ev, src=src, dst=dst, pkt_ipv4=pkt_ipv4, pkt_tcp=pkt_tcp)

    def send_pkt(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arpre(self, datapath, port, src_mac, dst_mac, src_ip, dst_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
        self.send_pkt(datapath, port, pkt)

    def install_path(self, src_dpid, dst_dpid, src_port, dst_port, ev, src, dst, pkt_ipv4, pkt_tcp):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mid_path = None

        mid_path = self.short_path(src=src_dpid, dst=dst_dpid)

        if mid_path is None:
            return
        self.path = None
        self.path = [(src_dpid, src_port)] + mid_path + [(dst_dpid, dst_port)]

        self.logger.info("path : %s", str(self.path))

        for i in xrange(len(self.path) - 2, -1, -2):
            datapath_path = self.datapaths[self.path[i][0]]
            match = parser.OFPMatch(in_port=self.path[i][1], eth_src=src, eth_dst=dst, eth_type=0x0800,
                                    ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst)

            if i < (len(self.path) - 2):
                actions = [parser.OFPActionOutput(self.path[i + 1][1])]
            else:
                actions = [parser.OFPActionSetField(eth_dst=self.ip_to_mac.get(pkt_ipv4.dst)),
                            parser.OFPActionOutput(self.path[i + 1][1])]

            self.add_flow(datapath_path, 100, match, actions, datapath_path.id, idle_timeout=0, hard_timeout=0)
        # time_install = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        # self.logger.info("time_install: %s", time_install)

    def short_path(self, src, dst, bw=0):
        if src == dst:
            return []
        result = defaultdict(lambda: defaultdict(lambda: None))
        distance = defaultdict(lambda: None)

        # the node is checked
        seen = [src]

        # the distance to src
        distance[src] = 0

        w = 1  # weight
        while len(seen) < len(self.src_links):
            node = seen[-1]
            if node == dst:
                break
            for (temp_src, temp_dst) in self.src_links[node]:
                if temp_dst not in seen:
                    temp_src_port = self.src_links[node][(temp_src, temp_dst)][0]
                    temp_dst_port = self.src_links[node][(temp_src, temp_dst)][1]
                    if (distance[temp_dst] is None) or (distance[temp_dst] > distance[temp_src] + w):
                        distance[temp_dst] = distance[temp_src] + w
                        # result = {"dpid":(link_src, src_port, link_dst, dst_port)}
                        result[temp_dst] = (temp_src, temp_src_port, temp_dst, temp_dst_port)
            min_node = None
            min_path = 999
            # get the min_path node
            for temp_node in distance:
                if (temp_node not in seen) and (distance[temp_node] is not None):
                    if distance[temp_node] < min_path:
                        min_node = temp_node
                        min_path = distance[temp_node]
            if min_node is None:
                break
            seen.append(min_node)

        path = []

        if dst not in result:
            return None

        while (dst in result) and (result[dst] is not None):
            path = [result[dst][2:4]] + path
            path = [result[dst][0:2]] + path
            dst = result[dst][0]
        return path

    def long_path(self, src, dst, count=None):
        nodes = [Node(src, None)]
        seen = []
        result = []
        paths = []
        while nodes:
            node = nodes.pop(0)
            src_id = node.v;
            seen.append(src_id)
            for (temp_src, temp_dst) in self.src_links[src_id]:
                if temp_dst in seen:
                    continue
                if temp_dst == dst:
                    result.append(Node(dst, node))
                    continue
                nodes.append(Node(temp_dst, node))
        if not result:
            return None
        n = 0
        for node in result:
            p = node
            path = []
            while p.p is not None:
                path.insert(0, (p.v, self.src_links[p.p.v][(p.p.v, p.v)][1]))
                path.insert(0, (p.p.v, self.src_links[p.p.v][(p.p.v, p.v)][0]))
                p = p.p
            paths.append(path)
            n = n + 1
        if (src, dst) not in self.count or self.count[(src, dst)] is None:
            self.count[(src, dst)] = -1
        self.count[(src, dst)] = (self.count[(src, dst)] + 1) % n
        return paths[self.count[(src, dst)]]

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave, event.EventPortAdd, event.EventPortDelete, event.EventPortModify, event.EventLinkAdd, event.EventLinkDelete])
    def get_topology(self, ev):
        links_list = get_link(self.topology_api_app, None)
        self.src_links.clear()
        for link in links_list:
            sw_src = link.src.dpid
            sw_dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            src_port_name = link.src.name
            dst_port_name = link.dst.name
            self.port_name_to_num[src_port_name] = src_port
            self.port_name_to_num[dst_port_name] = dst_port
            self.src_links[sw_src][(sw_src, sw_dst)] = (src_port, dst_port)
            self.src_links[sw_dst][(sw_dst, sw_src)] = (dst_port, src_port)

    @staticmethod
    def delete_flow(datapath, match, out_port):
        mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
                                                 match=match, out_port = 3,
                                                 cookie=datapath.id,
                                                 command=datapath.ofproto.OFPFC_DELETE,
                                                 idle_timeout=0, hard_timeout=0)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPortStatus, [MAIN_DISPATCHER])
    def get_OFPPortStatus_msg(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        if msg.reason == ofproto.OFPPR_MODIFY:
            if msg.desc.state == 4:
                if (dp.id, msg.desc.port_no) not in self.entry \
                        or self.entry[(dp.id, msg.desc.port_no)] is None:
                    return
        #print "up"
                src = dp.id
                src_port = msg.desc.port_no
                if (src, src_port) in self.to_delete:
                    self.to_delete.remove((src, src_port))
                for id_del in self.datapaths:
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(eth_src=self.entry[src, src_port][0],eth_dst=self.entry[(src, src_port)][1])
                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                    self.remove_flows(self.datapaths[id_del], 0, self.entry[src, src_port][0], self.entry[src, src_port][1])
                    self.remove_flows(self.datapaths[id_del], 0, self.entry[src, src_port][1], self.entry[src, src_port][0])
                self.entry.pop((src, src_port))
            if msg.desc.state == 1:
                src = dp.id
                src_port = msg.desc.port_no
                self.to_delete.append((src, src_port))
                self.send_flow_stats_request(dp)


    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        cookie_mask = 2;
        match = ofp_parser.OFPMatch()
        cookie = datapath.id
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        if len(ev.msg.body) < 2:
            return
        dpid = ev.msg.body[1].cookie
        for (src, src_port) in self.to_delete:
            if src == dpid:
                for stat in ev.msg.body:
                    if 'eth_src' in stat.match:
                        for act in stat.instructions[0].actions:
                            if isinstance(act, OFPActionOutput):
                                if act.port == src_port:
                                    self.entry[(src, src_port)]=(stat.match['eth_src'], stat.match['eth_dst'])
                                    self.to_delete.remove((src, src_port))
                                    for datapath_path in self.datapaths:
                                        if 'ofproto_parser' not in self.datapaths[datapath_path].__dict__:
                                            continue
                                        parser = self.datapaths[datapath_path].ofproto_parser
                                        ofproto = self.datapaths[datapath_path].ofproto
                                        #match1 = parser.OFPMatch(eth_src=stat.match['eth_src'],eth_dst=stat.match['eth_dst'])
                                        #match2 = parser.OFPMatch(eth_src=stat.match['eth_dst'],eth_dst=stat.match['eth_src'])
                                        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                                        self.remove_flows(self.datapaths[datapath_path], 0, eth_src=stat.match['eth_src'],eth_dst=stat.match['eth_dst'])


    def remove_flows(self, datapath, table_id, eth_src, eth_dst):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        #ofproto = datapath.ofproto
        match = parser.OFPMatch(eth_src=eth_src, eth_dst=eth_dst)
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        match, instructions)
        datapath.send_msg(flow_mod)


    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod

