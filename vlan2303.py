# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""

#Theodoros Tsourdinis 2303

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import vlan


LANA = "192.168.1"
LANB = "192.168.2"
H1 = "00:00:00:00:01:02"
R1_left_mac = "00:00:00:00:01:01"
R2_right_mac = "00:00:00:00:02:01"
R1_left_ip = "192.168.1.1"
R2_right_ip = "192.168.2.1"
H2 = "00:00:00:00:02:02"
H3 = "00:00:00:00:02:03"
H4 = "00:00:00:00:01:03"
trunc_port = 1
broadcast = "ff:ff:ff:ff:ff:ff"
broadcast_flag = 0
vlan100 = 100
vlan200 = 200


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.vlan_to_mac_to_port = {} #Hash Table

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        global broadcast_flag

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        #Hash Table Initialization
        self.vlan_to_mac_to_port.setdefault(dpid,{vlan100:{},vlan200:{}})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)


        #SWITCH2
        if dpid == 0x2:
            if msg.in_port == 3: #VLAN100
                self.vlan_to_mac_to_port[dpid][vlan100][src] = msg.in_port
                
                
                if dst == broadcast:
                    
                    #Send it to the router and send it to trunc port ( with VLANID: 100) / Adding the flow
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionOutput(2), datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    #self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)
                
                
                elif dst==H4:
                    
                    if dst in self.vlan_to_mac_to_port[dpid][vlan100]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_dst=haddr_to_bin(dst))
                        #Encapsulate it and send it to trunc port
                        actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)                        
                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                
                
             
                elif dst == R1_left_mac:
                     
                     if dst in self.vlan_to_mac_to_port[dpid][vlan100]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                        #Send it to the router 
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)

                     else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    

                elif dst == H2 or dst == H3:
                    if R1_left_mac in self.vlan_to_mac_to_port[dpid][vlan100]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                        #Send it to the router 
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)

                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    
                
                
                
            
            if msg.in_port == 2: #VLAN100
                self.vlan_to_mac_to_port[dpid][vlan100][src] = msg.in_port
                
                
                if dst == H1:
                    if dst in self.vlan_to_mac_to_port[dpid][vlan100]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(3),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                
                
                elif dst == H4:
                    if dst in self.vlan_to_mac_to_port[dpid][vlan100]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                        #Encapsulate it and send it to trunc port
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(3),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                
                
                elif dst == broadcast:
                    #Broadcast
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionOutput(3),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    #self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)        
                    
                
                    
            
            if msg.in_port == 4: #VLAN200
                self.vlan_to_mac_to_port[dpid][vlan200][src] = msg.in_port 
                if  dst == H1 or dst == H3 or dst == H4 or dst == R1_left_mac or dst == R2_right_mac:      
                    #Adding the flow and Send it to trunc port (VLANID: 200) / Adding the flow
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)
                if dst == broadcast:
                    #Adding the flow and Send it to trunc port (VLANID: 200) / Adding the flow
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    #self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)
                    
            
            
            if msg.in_port == 1: #Trunc Port
                parser = datapath.ofproto_parser
                if eth.ethertype == ether_types.ETH_TYPE_8021Q :
                    vlan_header = pkt.get_protocols(vlan.vlan) 
                    v_id = vlan_header[0].vid
                    
                    if v_id == 100:
                        self.vlan_to_mac_to_port[dpid][vlan100][src] = msg.in_port
                        
                        if dst == H1:
                            if dst in self.vlan_to_mac_to_port[dpid][vlan100]:
                                out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                                match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                            else:
                                #broadcast
                                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(2), parser.OFPActionOutput(3)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                                
                
                        elif dst == H2 or dst == H3:
                                if R1_left_mac in self.vlan_to_mac_to_port[dpid][vlan100]:
                                    out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                                    match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id, in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                                    actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                    self.add_flow(datapath, match, actions)
                                    self._packet_out(datapath,msg,actions)
                                else:
                                    out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                                    match = datapath.ofproto_parser.OFPMatch( dl_vlan = v_id,in_port=msg.in_port ,dl_dst=haddr_to_bin(dst))
                                    actions = [parser.OFPActionStripVlan(),parser.OFPActionOutput(2), parser.OFPActionOutput(3)]
                                    #self.add_flow(datapath, match, actions)
                                    self._packet_out(datapath,msg,actions)
                        
                        
                        elif dst == broadcast:
                            #broadcast
                                match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(2), parser.OFPActionOutput(3)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                        
                            
                        elif dst == R1_left_mac:
                            
                            if dst in self.vlan_to_mac_to_port[dpid][vlan100]:
                                    out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                                    match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port ,dl_dst=haddr_to_bin(dst))
                                    actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                    self.add_flow(datapath, match, actions)
                                    self._packet_out(datapath,msg,actions)
                            else:
                                match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(2), parser.OFPActionOutput(3)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                            
                        
                             
                        
                    if v_id == 200:
                        self.vlan_to_mac_to_port[dpid][vlan200][src] = msg.in_port
                        if dst == H2:
                            out_port = 4
                            match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                            actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                            self.add_flow(datapath, match, actions)
                            self._packet_out(datapath,msg,actions)

                        if dst == broadcast:
                            out_port = 4
                            match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                            actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                            #self.add_flow(datapath, match, actions)
                            self._packet_out(datapath,msg,actions)
                            
                    
        #SWITCH 3
        if dpid == 0x3:
            if msg.in_port == 3: #VLAN200
                self.vlan_to_mac_to_port[dpid][vlan200][src] = msg.in_port
                
            
                if dst == broadcast:
                    #Send it to the router / Adding the flow and Send it to trunc port (VLANID: 100) / Adding the flow
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    #self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)
            

                elif dst==H2:
                    if dst in self.vlan_to_mac_to_port[dpid][vlan200]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)                        
                    else:
                         #Send it to the router / Adding the flow and Send it to trunc port (VLANID: 100) / Adding the flow
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                
                elif dst == R2_right_mac:
                        if dst in self.vlan_to_mac_to_port[dpid][vlan200]:
                            out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                            #Send it to the router 
                            match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                            self.add_flow(datapath, match, actions)
                            self._packet_out(datapath,msg,actions)

                        else:
                            #broadcast
                            match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                            actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                            #self.add_flow(datapath, match, actions)
                            self._packet_out(datapath,msg,actions)
            
            
                elif dst==H1 or dst == H4:
                    if R2_right_mac in self.vlan_to_mac_to_port[dpid][vlan200]:
                            out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                            #Send it to the router 
                            match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                            self.add_flow(datapath, match, actions)
                            self._packet_out(datapath,msg,actions)

                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(2),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    
            

            if msg.in_port == 2: #VLAN200
                
                self.vlan_to_mac_to_port[dpid][vlan200][src] = msg.in_port
                
                if dst == H3:
                    if dst in self.vlan_to_mac_to_port[dpid][vlan200]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(3),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                
                    
                     
                elif dst == H2:
                    if dst in self.vlan_to_mac_to_port[dpid][vlan200]:
                        out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                        #Encapsulate it and send it to trunc port
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                    else:
                        #broadcast
                        match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                        actions = [datapath.ofproto_parser.OFPActionOutput(3),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                        #self.add_flow(datapath, match, actions)
                        self._packet_out(datapath,msg,actions)
                        
                        
                elif dst == broadcast:
                    #Broadcast
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionOutput(3),datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=200), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    #self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)  
                    
            
            if msg.in_port == 4: #VLAN100
                self.vlan_to_mac_to_port[dpid][vlan100][src] = msg.in_port
                if  dst == H1 or dst == H3 or dst == H2 or dst == R1_left_mac or dst == R2_right_mac:     
                    #Adding the flow and Send it to trunc port (VLANID: 100) / Adding the flow
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)
                if dst == broadcast:
                    #Adding the flow and Send it to trunc port (VLANID: 100) / Adding the flow
                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                    actions = [datapath.ofproto_parser.OFPActionVlanVid(vlan_vid=100), datapath.ofproto_parser.OFPActionOutput(trunc_port)]
                    #self.add_flow(datapath, match, actions)
                    self._packet_out(datapath,msg,actions)
                        
                     
            
            if msg.in_port == 1: #Trunc Port
                parser = datapath.ofproto_parser
                if eth.ethertype == ether_types.ETH_TYPE_8021Q :
                    vlan_header = pkt.get_protocols(vlan.vlan) 
                    v_id = vlan_header[0].vid
                    
                    if v_id == 200:
                        self.vlan_to_mac_to_port[dpid][vlan200][src] = msg.in_port
                
                        if dst == H3:
                            if dst in self.vlan_to_mac_to_port[dpid][vlan200]:
                                out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                            else:
                                #broadcast
                                match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port ,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(3), parser.OFPActionOutput(2)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                        
                        
                        elif dst == H4 or dst == H1:
                                if R2_right_mac in self.vlan_to_mac_to_port[dpid][vlan200]:
                                    out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                    actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                    self.add_flow(datapath, match, actions)
                                    self._packet_out(datapath,msg,actions)
                                else:
                                    out_port = self.vlan_to_mac_to_port[dpid][vlan100][dst]
                                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                    actions = [parser.OFPActionStripVlan(),parser.OFPActionOutput(3), parser.OFPActionOutput(2)]
                                    #self.add_flow(datapath, match, actions)
                                    self._packet_out(datapath,msg,actions)
                        
                        
                        elif dst == broadcast:
                            #broadcast
                                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(3), parser.OFPActionOutput(2)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                        
                        
                        elif dst==R2_right_mac:
                            
                            if dst in self.vlan_to_mac_to_port[dpid][vlan200]:
                                    out_port = self.vlan_to_mac_to_port[dpid][vlan200][dst]
                                    match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                    actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                    self.add_flow(datapath, match, actions)
                                    self._packet_out(datapath,msg,actions)
                            else:
                                match = datapath.ofproto_parser.OFPMatch(in_port=msg.in_port ,dl_vlan = v_id,dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(3), parser.OFPActionOutput(2)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)

                 

                    if v_id == 100:
                            self.vlan_to_mac_to_port[dpid][vlan100][src] = msg.in_port
                            if dst == H4:
                                out_port = 4
                                match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                            if dst == broadcast:
                                out_port = 4
                                match = datapath.ofproto_parser.OFPMatch(dl_vlan = v_id,in_port=msg.in_port, dl_dst=haddr_to_bin(dst))
                                actions = [parser.OFPActionStripVlan(), parser.OFPActionOutput(out_port)]
                                #self.add_flow(datapath, match, actions)
                                self._packet_out(datapath,msg,actions)
                                



        if dpid == 0x1A:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp.opcode == arp.ARP_REQUEST:
                   self.a_arp_conf(datapath, msg.in_port, eth, pkt_arp)
                   return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                if pkt_ipv4:
                    self._ra_ipv4_conf(datapath,msg.in_port,eth,pkt_ipv4,msg)
                    return
            return
        if dpid == 0x1B:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp.opcode ==arp.ARP_REQUEST:
                   self.b_arp_conf(datapath, msg.in_port, eth, pkt_arp)
                   return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                if pkt_ipv4:
                    self._rb_ipv4_conf(datapath,msg.in_port,eth,pkt_ipv4,msg)
                    return
            return
        
        
        #BASIC LAYER 2 FUNCTIONALITY         
        # if dst in self.mac_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][dst]
        # else:
        #     out_port = ofproto.OFPP_FLOOD

        # match = datapath.ofproto_parser.OFPMatch(
        #     in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        # actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     self.add_flow(datapath, match, actions)

        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data

        # out = datapath.ofproto_parser.OFPPacketOut(
        #     datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
        #     actions=actions, data=data)
        # datapath.send_msg(out)

    
    def a_arp_conf(self, datapath, port, pkt_ethernet, pkt_arp):

        if pkt_arp.dst_ip == '192.168.1.1':
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src='00:00:00:00:01:01'))
                pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,src_mac='00:00:00:00:01:01',src_ip='192.168.1.1',dst_mac=pkt_ethernet.src,dst_ip=pkt_arp.src_ip))
                self._send_packet(datapath, port, pkt)


    
    def b_arp_conf(self, datapath, port, pkt_ethernet, pkt_arp):

        if pkt_arp.dst_ip == '192.168.2.1':
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src='00:00:00:00:02:01'))
                pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,src_mac='00:00:00:00:02:01',src_ip='192.168.2.1',dst_mac= pkt_ethernet.src ,dst_ip=pkt_arp.src_ip))
                self._send_packet(datapath, port, pkt)

    
    
    def _ra_ipv4_conf(self,datapath,port,pkt_ethernet,pkt_ipv4,msg):
        
        parser = datapath.ofproto_parser
        if LANB in pkt_ipv4.dst:

            ofproto = datapath.ofproto

            out_port = 1

            match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_dst_mask = 24,nw_dst=pkt_ipv4.dst)

            actions = [parser.OFPActionSetDlSrc(dl_addr="00:00:00:00:03:01"),parser.OFPActionSetDlDst(dl_addr ="00:00:00:00:03:02"),datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            self.add_flow(datapath, match, actions)
            self._packet_out(datapath,msg,actions)

        elif LANA in pkt_ipv4.dst:

            ofproto = datapath.ofproto

            out_port = 2

            match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_dst_mask = 24,nw_dst=pkt_ipv4.dst)

            actions = [parser.OFPActionSetDlSrc(dl_addr="00:00:00:00:01:01"),parser.OFPActionSetDlDst(dl_addr ="ff:ff:ff:ff:ff:ff") ,datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            self.add_flow(datapath, match, actions)
            self._packet_out(datapath,msg,actions)

        else:
            self._handle_icmp(datapath,port,pkt_ethernet,pkt_ipv4,R1_left_mac, R1_left_ip,msg.data) 
        
	 
    def _rb_ipv4_conf(self,datapath,port,pkt_ethernet,pkt_ipv4,msg):
        
        parser = datapath.ofproto_parser
        if LANB in pkt_ipv4.dst:

            ofproto = datapath.ofproto

            out_port = 2

            match = datapath.ofproto_parser.OFPMatch(in_port=port, dl_type=ether_types.ETH_TYPE_IP, nw_dst_mask = 24,nw_dst=pkt_ipv4.dst)

            actions = [parser.OFPActionSetDlSrc(dl_addr="00:00:00:00:02:01"),parser.OFPActionSetDlDst(dl_addr ="ff:ff:ff:ff:ff:ff"),datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            self.add_flow(datapath, match, actions)
            self._packet_out(datapath,msg,actions)

        elif LANA in pkt_ipv4.dst:

            ofproto = datapath.ofproto

            out_port = 1

            match = datapath.ofproto_parser.OFPMatch(in_port=port,dl_type=ether_types.ETH_TYPE_IP,nw_dst_mask = 24,nw_dst=pkt_ipv4.dst)

            actions = [parser.OFPActionSetDlSrc(dl_addr="00:00:00:00:03:02"),parser.OFPActionSetDlDst(dl_addr ="00:00:00:00:03:01") ,datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            self.add_flow(datapath, match, actions)
            self._packet_out(datapath,msg,actions)
            
        
        else:
            self._handle_icmp(datapath,port,pkt_ethernet,pkt_ipv4,R2_right_mac,R2_right_ip,msg.data)
     

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, mac_src, ip_src , msg_data):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,dst=pkt_ethernet.src,src=mac_src))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=ip_src,proto=pkt_ipv4.proto))
        ip_datagram = bytearray()
        ip_datagram += msg_data[14:]
        data_len = int(len(ip_datagram) / 4)
        pkt.add_protocol(icmp.icmp(type_=3,code=1,csum=0,data=icmp.dest_unreach(data_len=data_len,data=ip_datagram)))
        self._send_packet(datapath, port, pkt)
    
    
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
            
    
    def _send_packet(self, datapath, port, pkt):
         ofproto = datapath.ofproto
         parser = datapath.ofproto_parser
        # self.logger.info("packet-out %s" % (pkt,))
         pkt.serialize()
         data = pkt.data
         actions = [parser.OFPActionOutput(port=port)]
         out = parser.OFPPacketOut(datapath=datapath,buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
         datapath.send_msg(out)



    def _packet_out(self,datapath,msg,actions):
            ofproto = datapath.ofproto
           #Sself.logger.info("packet-out %s" % (msg,))
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
            datapath.send_msg(out)