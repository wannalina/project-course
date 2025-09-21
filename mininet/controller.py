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

from webob import Response
import json

from lib.helper_funcs import cidr_to_network_mask, get_ip_proto_num

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
                'securtiy_rules': self.security_rules  
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
    def install_security_flow(self, datapath, match_dict, decision, priority=100):
        match_params = {}   # OpenFlow match fields

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # ensure ip traffic matching (IPv4)
        match_params['eth_type'] = 0x0800 

        # match source subnet
        if 'src_subnet' in match_dict:
            src_ip, src_mask = cidr_to_network_mask(match_dict['src_subnet'])
            if src_ip and src_mask:
                match_params['ipv4_src'] = (src_ip, src_mask)

        # match dst subnet
        if 'dst_subnet' in match_dict:
            dst_ip, dst_mask = cidr_to_network_mask(match_dict['dst_subnet'])
            if dst_ip and dst_mask:
                match_params['ipv4_dst'] = (dst_ip, dst_mask)

        # match ip protocol
        if 'ip_proto' in match_dict:
            proto_num = get_ip_proto_num(match_dict['ip_proto'])
            if proto_num:
                match_params['ip_proto'] = proto_num

        # match transport layer dst port
        if 'tp_dst' in match_dict and 'ip_proto' in match_dict:
            proto = match_dict['ip_proto'].lower()
            if proto == 'tcp':
                match_params['tcp_dst'] = match_dict['tp_dst']
            elif proto == 'udp':
                match_params['udp_dst'] = match_dict['tp_dst']

        match = parser.OFPMatch(**match_params)

        # if allow, normal forwarding; else drop packet
        if decision == 'allow':
            actions = []
            inst = [parser.OFPInstructionGotoTable(table_id=1)]
        else:
            actions = []
            inst = []

        #!! install flow
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=0
        )
        datapath.send_msg(mod)
        return f"Security rule installed: {decision} for {match_dict}"


    #TODO: function to handle anti-spoofing (needs improvement)
    def handle_anti_spoofing(self, action):
        results = []
        try:
            # iterate over switches and evaluate anti-spoofing rules
            for dpid, datapath in self.datapaths.items():
                # get hosts for switch
                switch_hosts = {mac: info for mac, info in self.host_table.items() if info['dpid'] == dpid}

                for mac, host_info in switch_hosts.items():
                    #TODO: install per-port validation rules
                    pass
                
                results.append(f"Switch {dpid}: Anti-spoofing rules evaluated")
            return results

        except Exception as e:
            self.logger.error(f"Error implementing anti-spoofing: {e}")
            return [f'[Anti-spoofing] Failed to apply anti-spoofing rules: {e}']


    #?? function to block denied services
    def block_services(self, action):
        results = []
        try:
            match_dict = action.get('match', {})

            # iterate over switches to install security rules
            for dpid, datapath in self.datapaths.items():
                result = self.install_security_flow(datapath, match_dict, 'deny', priority=180)
                results.append(f"Switch {dpid}: {result}")
            return results

        except Exception as e:
            self.logger.error(f"Error blocking inbound services: {e}")
            return [f'[Block Inbound] Failed to block inbound services: {e}']


    #?? function to handle blocking outbound services
    def block_outbound_services(self, action):
        results = []
        try:
            match_dict = action.get('match', {})


            for dpid, datapath in self.datapaths.items():
                result = self.install_security_flow(datapath, match_dict, 'deny', priority=170)
                results.append(f"Switch {dpid}: {result}")

            return results
        except Exception as e:
            self.logger.error(f"Error blocking outbound services: {e}")
            return [f'[Block Outbound] Failed to block outbound services: {e}']


    #?? handle whitelisting HTTPS to specified destinations
    def whitelist_https(self, action):
        try:
            # allow HTTPS to specific destinations
            match_dict = action.get('match', {})
            match_dict['ip_proto'] = 'tcp'
            match_dict['tp_dst'] = 443
            
            results = []
            for dpid, datapath in self.datapaths.items():
                result = self.install_security_flow(datapath, match_dict, 'allow', priority=250)
                results.append(f"Switch {dpid}: {result}")
            
            return results
        except Exception as e:
            self.logger.error(f"Error whitelisting HTTPS: {e}")
            return [f'[HTTPS Whitelist] Failed to whitelist HTTPS: {e}']


    # function to handle ingress filtering logic
    def ingress_filter(self, action, priority):
        results = []
        try:
            match_dict = action.get('match', {})    # match fields
            decision = action.get('decision', 'deny')   # allow/deny

            # loop through switches to install rule
            for dpid, datapath in self.datapaths.items():
                # check is switch in list
                if dpid not in self.security_rules:
                    self.security_rules[dpid] = {'ingress': [], 'egress': []}
                
                rule_entry = {
                    'match': match_dict,
                    'decision': decision,
                    'reason': action.get('reason', '')
                }
                self.security_rules[dpid]['ingress'].append(rule_entry)

                # install flow rule
                result = self.install_security_flow(datapath, match_dict, decision, priority=200)
                results.append(f"Switch {dpid}: {result}")
            return results

        except Exception as e: 
            self.logger.error(f"Error implementing ingress action: {e}")
            return [f'[Ingress filtering] Failed to apply ingress action: {e}']


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


    # event handler to set up stp config dynamically (called upon switch connection event)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _stp_switch_connected(self, ev):
        dpid = ev.dp.id
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


    # install table-miss flow entry
    def _install_table_miss_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # table-miss (send unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # table 0 miss (security stage)
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst,
            table_id=0, command=ofproto.OFPFC_ADD
        )
        datapath.send_msg(mod)

        # table 1 miss (forwarding stage)
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst,
            table_id=1, command=ofproto.OFPFC_ADD
        )
        datapath.send_msg(mod)


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
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # parse eth header
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # src/dst MAC addresses
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

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

        # install a flow to avoid packet_in next time (flow in unicast table 1)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions, table_id=1)

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
        elif ev.state == 'DEAD_DISPATCHER':
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
                action_direction = action.get("direction")
                
                if action_direction == 'ingress':
                    result = self.controller.ingress_filter(action)
                    results.extend(result)
                elif action_direction == 'egress':
                    result = self.controller.egress_filter(action)
                    results.extend(result)
                '''else:
                    # handle actions without explicit direction
                    if 'src_subnet' in action.get('match', {}):
                        # source-based rules typically ingress
                        result = self.controller.ingress_filter(action)
                        results.extend(result)
                    elif 'dst_subnet' in action.get('match', {}):
                        # destination-based rules typically egress  
                        result = self.controller.egress_filter(action)
                        results.extend(result)
                    else:
                        # apply to both if unclear
                        result_ingress = self.controller.ingress_filter(action)
                        result_egress = self.controller.egress_filter(action)
                        results.extend(result_ingress)
                        results.extend(result_egress)
                    '''

            return Response(content_type='application/json', body=json.dumps({"results": results}, indent=2).encode('utf-8'))

        except Exception as e:
            error_response = {"error": f"Failed to process actions: {str(e)}"}
            return Response(content_type='application/json', body=json.dumps(error_response).encode('utf-8'), status=500)