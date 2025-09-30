# this controller is adapted from the ryu simple_switch_13_step.py

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app import simple_switch_13
from ryu.app.wsgi import ControllerBase, route
from ryu.app.wsgi import WSGIApplication
from ryu.lib.packet import ipv4 as ipv4pkt
from ryu.lib.packet import arp as arppkt
from ryu.lib.packet import ether_types

from webob import Response
import json
import time
import ipaddress

from helper_funcs import cidr_to_network_mask, get_ip_proto_num

# SDN controller; extends RYU SimpleSwitch13 with added stp
class SimpleSwitch13(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'stplib': stplib.Stp
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}   # mac-to-port mapping (packet_in)
        self.datapaths = {}     # switches
        self.host_table = {}    # host attachment to switch
        self.port_stats = {}    # port counters
        self.port_desc_stats = {} # operational states / features of ports
        self.flow_stats = {}    # flow entries
        self.stp_port_state = {}  # stp port states
        self.security_rules = {}  # ingress/egress policies per switch
        self.ip_bindings = {}   # mappings for anti-spoofing
        self.protected_ips = set()

        # sav components
        self.sav_enabled = True     # sav enabled by default
        self.allowed_subnets = {}  # allowed subnets for each switch
        self.host_bindings = {}    # host bindings
        self.blocked_ips = set()    # list of blocked ip addresses

        # inject stp and wsgi contexts
        self.stp = kwargs['stplib']
        wsgi = kwargs['wsgi']
        wsgi.register(IntentAPI, {'controller': self})

        self.base_stp_config = {
            'bridge': {'priority': 0x8000},
        }

    # function to retrieve network state data
    def get_network_state(self):
        try: 
            # iterate through datapaths to get flow entries
            for dpid, dp in self.datapaths.items():
                parser = dp.ofproto_parser
                ofproto = dp.ofproto

                # request flow stats
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)

                # request port stats
                port_req = parser.OFPPortStatsRequest(dp, 0, ofproto.OFPP_ANY)
                dp.send_msg(port_req)

                # request port descriptions
                port_desc_req = parser.OFPPortDescStatsRequest(dp)
                dp.send_msg(port_desc_req)

            # define state object for snapshot
            state = {
                "switches": list(self.datapaths.keys()),
                'host_table': self.host_table,
                'mac_table': self.mac_to_port,
                'port_stats': self.port_stats,
                'stp_port_states': self.stp_port_state,
                'port_description_stats': self.port_desc_stats,
                'flow_tables': self.flow_stats,
                'security_rules': self.security_rules  
            }

            for dpid, dp in self.datapaths.items():
                # populate latest vals
                state["flow_tables"][dpid] = self.flow_stats.get(dpid, [])
                state["port_stats"][dpid] = self.port_stats.get(dpid, [])
                state["port_description_stats"][dpid] = self.port_desc_stats.get(dpid, [])

            return state

        except Exception as e: 
            print(f"Error getting network state: {e}")
            return None


    # modified add_flow to support table_id
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # build instruction to apply action immediately
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # if buffer id, install flow and apply to buffered packet; else install flow
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)


    # function to delete flow entries
    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # loop through known dsts; delete matching flows
        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)


    # function to install security flow rule
    def install_security_flow(self, datapath, match_dict, decision, priority=20000, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # match ipv4
        match_params = {'eth_type': 0x0800}

        # get src address (accept cidr or ip)
        src = match_dict.get('src_subnet', '')
        if src:
            if '/' in src:
                src_ip, src_mask = cidr_to_network_mask(src)
                if src_ip and src_mask:
                    match_params['ipv4_src'] = (src_ip, src_mask)
            else:
                match_params['ipv4_src'] = src  # exact host

        # get dst address
        dst = match_dict.get('dst_subnet', '')
        if dst:
            if '/' in dst:
                dst_ip, dst_mask = cidr_to_network_mask(dst)
                if dst_ip and dst_mask:
                    match_params['ipv4_dst'] = (dst_ip, dst_mask)
            else:
                match_params['ipv4_dst'] = dst  # exact host

        # get protocol
        ip_proto_str = (match_dict.get('ip_proto') or '').lower()
        if decision.lower() == 'deny':
            if ip_proto_str not in ('tcp', 'udp'):
                return "Denied installing rule: 'ip_proto' must be 'tcp' or 'udp'"

        if ip_proto_str in ('tcp', 'udp'):
            proto_num = get_ip_proto_num(ip_proto_str)

            if proto_num is not None:
                match_params['ip_proto'] = proto_num

        # transport dst port (only if proto given)
        if 'tp_dst' in match_dict and ip_proto_str in ('tcp', 'udp'):
            if ip_proto_str == 'tcp':
                match_params['tcp_dst'] = int(match_dict['tp_dst'])
            else:
                match_params['udp_dst'] = int(match_dict['tp_dst'])

        match = parser.OFPMatch(**match_params)

        # determine instructions and cookie based on decision
        if decision.lower() == 'allow':
            inst = [parser.OFPInstructionGotoTable(1)]
            cookie = 0x5EC00000 | 0x0001    # security cookies (allow rule)
        else:
            inst = []
            cookie = 0x5EC00000 | 0x0002    # security cookie (deny rule)

        self.logger.info(match_params)

        mod = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=inst,
            cookie=cookie,
            command=ofproto.OFPFC_ADD
        )
        datapath.send_msg(mod)
        return f"Security rule installed: {decision} for {match_dict}"


    # function to configure allowed subnets for switch
    def configure_sav_subnets(self, dpid, subnets):
        valid_subnets = []
        try:
            for subnet in subnets:
                # validate cidr notation
                ipaddress.IPv4Network(subnet, strict=False)
                valid_subnets.append(subnet)

            self.allowed_subnets[dpid] = valid_subnets
            self.logger.info(f"Configured {len(valid_subnets)} allowed subnets for switch {dpid}")
            return True

        except Exception as e:
            self.logger.error(f"Error configuring subnets for source address validation: {e}")
            return False


    # function to check if source ip allowed based on configed sbubnets
    def is_source_allowed(self, dpid, src_ip):
        # if not in allowed subnets, no configuration for switch
        if dpid not in self.allowed_subnets:
            return True

        try:
            src_addr = ipaddress.IPv4Address(src_ip)
            for subnet in self.allowed_subnets[dpid]:
                network = ipaddress.IPv4Network(subnet, strict=False)
                if src_addr in network:
                    return True
            return False

        except ValueError:
            return False


    # function to implement FCFS binding validation
    def validate_host_binding(self, dpid, src_ip, src_mac, in_port):
        # no bindings exist
        if dpid not in self.host_bindings:
            self.host_bindings[dpid] = {}

        current_time = time.time()

        # check if ip has binding already
        if src_ip in self.host_bindings[dpid]:
            existing = self.host_bindings[dpid][src_ip]

            # check do mac address and port match
            if existing['mac'] == src_mac and existing['port'] == in_port:
                return True, "Valid existing binding"
            else:
                return False, f"IP {src_ip} bound to different MAC/port"

        # create new binding
        self.host_bindings[dpid][src_ip] = {
            'mac': src_mac,
            'port': in_port,
            'first_seen': current_time
        }

        self.logger.info(f"Created new binding: {dpid} - {src_ip} -> {src_mac}:{in_port}")
        return True, "New binding created"


    # function to install flow rule to block traffic from source ip
    def block_source_ip(self, dpid, src_ip):
        try:
            if not src_ip:
                self.logger.error("block_source_ip called with empty src_ip")
                return False

            try:
                ipaddress.IPv4Address(src_ip)

            except Exception as e:
                self.logger.error(f"block_source_ip invalid IPv4: {src_ip}")
                return False

            dp = self.datapaths.get(dpid)
            if not dp:
                return False

            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)

            # no instructions, tag with cookie to del later (drop); includes sav cookie
            mod = parser.OFPFlowMod(
                datapath=dp, table_id=1, priority=25000,
                match=match, instructions=[],
                cookie=0xA11E0001, command=ofp.OFPFC_ADD
            )
            dp.send_msg(mod)
            self.blocked_ips.add(src_ip)

            self.blocked_ips.add(src_ip)
            self.logger.warning(f"BLOCKED source IP {src_ip} on switch {dpid}")
            return True

        except Exception as e:
            self.logger.error(f"Error blocking source IP {src_ip}: {e}")
            return False


    # function to handle source address validation
    def handle_sav_actions(self, action):
        results = []
        try:
            # configure allowed sav subnets
            if "sav_subnets" in action:
                subnet_config = action["sav_subnets"]
                for dpid_str, subnets in subnet_config.items():
                    try:
                        dpid = int(dpid_str)
                        if self.configure_sav_subnets(dpid, subnets):
                            results.append(f"[SAV] Configured subnets for switch {dpid}: {subnets}")
                        else:
                            results.append(f"[SAV] Failed to configure subnets for switch {dpid}")
                    except ValueError:
                        results.append(f"[SAV] Invalid switch ID: {dpid_str}")

            # enable or disable sav
            if "sav_enabled" in action:
                self.sav_enabled = bool(action["sav_enabled"])
                results.append(f"[SAV] {'Enabled' if self.sav_enabled else 'Disabled'}")

            # clear bindings
            if action.get("clear_bindings", False):
                cleared_count = sum(len(bindings) for bindings in self.host_bindings.values())
                self.host_bindings.clear()
                results.append(f"[SAV] Cleared {cleared_count} host bindings")

            # clear blocked IPs
            if action.get("clear_blocked", False):
                # delete flow rules for blocked IPs
                for dpid, dp in self.datapaths.items():
                    parser = dp.ofproto_parser
                    ofp = dp.ofproto
                    # delete all sav-tagged entries in table 1
                    mod = parser.OFPFlowMod(
                        datapath=dp, table_id=1,
                        command=ofp.OFPFC_DELETE,
                        out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                        cookie=0xA11E0001, cookie_mask=0xFFFFFFFF,
                        match=parser.OFPMatch()
                    )
                    dp.send_msg(mod)
                blocked_count = len(self.blocked_ips)
                self.blocked_ips.clear()
                results.append(f"[SAV] Unblocked {blocked_count} IP addresses (cookie wipe)")

            return {"results": results}

        except Exception as e:
            self.logger.error(f"Error handling SAV actions: {e}")
            return {"results": [f"[SAV] Error: {str(e)}"]}



    # function to handle blocking outbound services
    def block_outbound_services(self, action):
        results = []
        try:
            match_dict = action.get('match', {})

            for dpid, datapath in self.datapaths.items():
                result = self.install_security_flow(datapath, match_dict, 'deny', priority=200)
                results.append(f"Switch {dpid}: Outbound service blocked - {result}")

            return results
        except Exception as e:
            self.logger.error(f"Error blocking outbound services: {e}")
            return [f'[Outbound Block] Failed: {e}']


    # function to handle whitelisting HTTPS to specified destinations
    def whitelist_https(self, action):
        results = []
        try:
            match_dict = action.get('match', {})
            
            # Validate required fields
            if not match_dict.get('dst_subnet'):
                return [f'[HTTPS Whitelist] Failed: dst_subnet required for whitelisting']
            
            dst_subnet = match_dict['dst_subnet']
            src_subnet = match_dict.get('src_subnet', None)
            
            for dpid, datapath in self.datapaths.items():
                try:
                    # allow HTTPS to whitelisted dsts (high priority)
                    allow_match = {
                        'dst_subnet': dst_subnet,
                        'ip_proto': 'tcp',
                        'tp_dst': 443
                    }

                    if src_subnet:
                        allow_match['src_subnet'] = src_subnet

                    result = self.install_security_flow(
                        datapath, allow_match, 'allow', 
                        priority=30000, table_id=0
                    )
                    results.append(f"Switch {dpid}: HTTPS allowed to {dst_subnet} - {result}")

                    # if source specified, block HTTPS from that subnet to other dsts
                    if src_subnet:
                        block_match = {
                            'src_subnet': src_subnet,
                            'ip_proto': 'tcp',
                            'tp_dst': 443
                        }

                        block_result = self.install_security_flow(
                            datapath, block_match, 'deny', 
                            priority=25000, table_id=0
                        )
                        results.append(f"Switch {dpid}: HTTPS blocked from {src_subnet} to others - {block_result}")

                except Exception as e:
                    results.append(f"Switch {dpid}: HTTPS whitelist failed - {str(e)}")

            return results

        except Exception as e:
            self.logger.error(f"Error whitelisting HTTPS: {e}")
            return [f'[HTTPS Whitelist] Failed: {str(e)}']


    # function to handle ingress filtering logic
    def ingress_filter(self, action):
        results = []
        try:
            match_dict = action.get('match', {})
            decision = action.get('decision', 'deny')

            for dpid, datapath in self.datapaths.items():
                if dpid not in self.security_rules:
                    self.security_rules[dpid] = {'ingress': [], 'egress': []}
                
                rule_entry = {
                    'match': match_dict,
                    'decision': decision,
                    'reason': action.get('reason', '')
                }
                self.security_rules[dpid]['ingress'].append(rule_entry)

                result = self.install_security_flow(datapath, match_dict, decision, priority=20000, table_id=0)
                results.append(f"Switch {dpid}: Ingress - {result}")
            return results

        except Exception as e: 
            self.logger.error(f"Error implementing ingress action: {e}")
            return [f'[Ingress filtering] Failed: {e}']


    # function to handle egress filtering logic
    def egress_filter(self, action):
        results = []
        try:
            match_dict = action.get('match', {})
            decision = action.get('decision', 'deny')

            # apply rule to all switches for egress
            for dpid, datapath in self.datapaths.items():
                # check switch exists in list
                if dpid not in self.security_rules:
                    self.security_rules[dpid] = {'ingress': [], 'egress': []}
                
                rule_entry = {
                    'match': match_dict,
                    'decision': decision,
                    'reason': action.get('reason', '')
                }
                self.security_rules[dpid]['egress'].append(rule_entry)

                # install rule
                result = self.install_security_flow(datapath, match_dict, decision, priority=150)
                results.append(f"Switch {dpid}: {result}")
            return results

        except Exception as e: 
            self.logger.error(f"Error implementing egress action: {e}")
            return [f'[Egress filtering] Failed to apply egress action: {e}']


    # function to drop https traffic by default
    def install_default_https_drop(self, datapath):
        ofp = datapath.ofproto
        p = datapath.ofproto_parser

        # drop TCP dst 443 (HTTPS over TCP)
        match_tcp = p.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=443)
        mod_tcp = p.OFPFlowMod(datapath=datapath, table_id=0, priority=10000,
                            match=match_tcp, instructions=[],  # no instructions = drop
                            cookie=0x5EC0DE43, command=ofp.OFPFC_ADD)
        datapath.send_msg(mod_tcp)

        # drop UDP dst 443 (HTTP/3 / QUIC)
        match_udp = p.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=443)
        mod_udp = p.OFPFlowMod(datapath=datapath, table_id=0, priority=10000,
                            match=match_udp, instructions=[],
                            cookie=0x5EC0DE43, command=ofp.OFPFC_ADD)
        datapath.send_msg(mod_udp)


    # event handler to set up stp config dynamically (called upon switch connection event)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _stp_switch_connected(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        self.logger.info("STP: Switch connected with DPID %s", dpid)

        # set dynamic STP config per switch
        if dpid == dpid_lib.str_to_dpid('0000000000000001'):
            config = {'bridge': {'priority': 0x8000}}
        elif dpid == dpid_lib.str_to_dpid('0000000000000002'):
            config = {'bridge': {'priority': 0x9000}}
        else:
            config = self.base_stp_config

        # apply config
        self.stp.set_config({dpid: config})
        self.logger.info("STP config applied to DPID %s: %s", dpid, config)

        # register switch and install table-miss pipeline
        self.datapaths[dpid] = dp
        self.install_table_miss_flow(dp)

        # drop https by default
        self.install_default_https_drop(dp)


    # install table-miss flow entry
    def install_table_miss_flow(self, datapath):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        # table 0 miss (go to table 1)
        instruction_t0 = [parser.OFPInstructionGotoTable(1)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, priority=0,
            match=match, instructions=instruction_t0, 
            command=ofp.OFPFC_ADD
        ))

        # table 1 miss (go to table 2)
        instruction_t1 = parser.OFPInstructionGotoTable(2)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=1, priority=0,
            match=match, instructions=[instruction_t1],
            command=ofp.OFPFC_ADD
        ))

        # table 1 miss (send to packet_in)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        instruction_t2 = parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=2, priority=0,
            match=match, instructions=[instruction_t2],
            command=ofp.OFPFC_ADD
        ))


    # event handler to parse each flow entry to a dict
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        flows = []

        for stat in ev.msg.body:
            actions = []

            # get output actions
            for inst in stat.instructions:
                if hasattr(inst, "actions"):
                    for a in inst.actions:
                        if a.__class__.__name__ == "OFPActionOutput":
                            actions.append({"type": "output", "port": a.port})

            # apply simplified flow view
            flows.append({
                "priority": stat.priority,
                "match": str(stat.match),
                "actions": actions,
                "packets": stat.packet_count,
                "bytes": stat.byte_count,
            })
        self.flow_stats[dpid] = flows


    # event handler to get port description stats into dict
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def _port_desc_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.port_desc_stats[dpid] = [vars(p) for p in ev.msg.body]


    # event handler to get per-port counters
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        self.port_stats[dpid] = [vars(stat) for stat in ev.msg.body]


    # event handler to handle packet_in event
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        src_ip = None
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # parse eth header
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # src/dst MAC addresses
        dst = eth.dst
        src = eth.src

        # avoid noise from LLPD
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # sav (ipv4 path)
        ip4 = pkt.get_protocol(ipv4pkt.ipv4)
        if ip4 and self.sav_enabled:
            src_ip = ip4.src

            # check allowed subnets
            if not self.is_source_allowed(dpid, src_ip):
                self.logger.warning(f"SAV: Source {src_ip} not in allowed subnets on switch {dpid}")
                self.block_source_ip(dpid, src_ip)   # installs drop in table 1
                return

            # check FCFS host binding (IP <--> MAC/port)
            ok, reason = self.validate_host_binding(dpid, src_ip, src, in_port)
            if not ok:
                self.logger.warning(f"SAV: Binding violation - {reason}")
                self.block_source_ip(dpid, src_ip)
                return

        # arp learning path (keeps bindings fresh, also filtered)
        arp = pkt.get_protocol(arppkt.arp)
        if arp and self.sav_enabled:
            arp_ip = arp.src_ip
            arp_mac = arp.src_mac
            if not arp_ip:   # safety
                return
            if not self.is_source_allowed(dpid, arp_ip):
                self.logger.warning(f"SAV: ARP source {arp_ip} not allowed on switch {dpid}")
                return
            self.validate_host_binding(dpid, arp_ip, arp_mac, in_port)

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn mac address to avoid FLOOD next time (switch ingress port mapping)
        self.mac_to_port[dpid][src] = in_port
        self.host_table[src] = {"dpid": dpid, "port": in_port}

        # decide egress port (learned port; else FLOOD)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install unicast learning flow in table 2
        if dst != "ff:ff:ff:ff:ff:ff":
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions, table_id=2)

        # send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    # event handler to handle topology change
    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        # remove learned unicast flows, clear L2 learning table
        if dp.id in self.mac_to_port:
            self.delete_flow(dp)
            del self.mac_to_port[dp.id]


    # event handler to track datapaths
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Registering datapath: %s", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info("Unregistering datapath: %s", datapath.id)
                self.datapaths.pop(datapath.id, None)


    # event handler to handle port state change
    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        self.stp_port_state.setdefault(ev.dp.id, {})[ev.port_no] = ev.port_state
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                        dpid_str, ev.port_no, of_state[ev.port_state])



# Intent API for Ryu controller
class IntentAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(IntentAPI, self).__init__(req, link, data, **config)
        self.controller = data['controller']


    # route to fetch current network state
    @route('intent', '/intent/get-state', methods=['GET'])
    def get_state(self, req, **kwargs):
        state = self.controller.get_network_state()

        res_body = json.dumps(state).encode('utf-8')
        return Response(content_type='application/json', body=res_body)


    # route to implement new actions in controller
    @route('intent', '/intent/implement', methods=['POST'])
    def post_action(self, req, **kwargs):
        try:
            request_data = req.json or {}
            actions = request_data.get('actions', [])
            results = []

            # loop through all actions
            for action in actions:
                action_direction = action.get("direction", "")
                action_type = action.get("decision", "")

                # source address validation (anti-spoofing)
                if any(k in action for k in ("sav_subnets", "sav_enabled", "clear_bindings", "clear_blocked")):
                    result = self.controller.handle_sav_actions(action)

                # block inbound services
                elif action_direction == 'ingress':
                    result = self.controller.ingress_filter(action)

                # block outbound services
                elif action_direction == 'egress':
                    result = self.controller.egress_filter(action)

                elif action_type == "whitelist":
                    result = self.controller.whitelist_https(action)

                results.append(result)

            return Response(content_type='application/json', body=json.dumps({"results": results}).encode('utf-8'))

        except Exception as e:
            error_response = {"error": f"Failed to process actions: {str(e)}"}
            return Response(content_type='application/json', body=json.dumps(error_response).encode('utf-8'), status=500)