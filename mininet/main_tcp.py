from collections import defaultdict
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
from pox.lib.packet.tcp import *
import time

from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
import pandas as pd
from pox.lib.packet.ethernet import ethernet,ETHER_BROADCAST

from pox.lib.packet.ipv6 import ipv6
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp
from pox.lib.addresses import IPAddr, EthAddr
import threading

from pox.lib.packet.udp import udp
import tkinter as tk


import numpy as np
import tensorflow as tf
import numpy as np
from gui.main import main, displayAlert
import threading
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

aliassajut= 0
newx=0
oldx=0
model = tf.keras.models.load_model('model_1.h5')
print('\n\n MODEL LOADED \n\n ')
prevResults = []



log = core.getLogger()

j = 0
data={
   'destination':[],
   'protocol':[],
   'dst_host_same_src_port_rate': [],
   'dst_host_srv_count':[],
   'dst_host_same_srv_rate': [],
   'src_bytes' :[],
   'land':[],
   'tcp_flags' : [],
   'count':[],
   'wrongfragments' : []
}

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class LearningSwitch (object):
  
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent
    self.connections={}
    self.dst_host_service_count = {}
    self.dst_host_connections = defaultdict(lambda: defaultdict(int))
    self.connection_counts={}
    self.timestamp=time.time()
    self.connection_timestamps= time.time()
    self.clearCount()
    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  
  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    packet = event.parsed
    if packet.type == packet.IP_TYPE:
          ip_packet = packet.find('ipv4')
          if ip_packet.protocol == ip_packet.TCP_PROTOCOL:   
                src_ip = ip_packet.srcip
                dst_ip = ip_packet.dstip
                src_port = ip_packet.payload.srcport
                dst_port = ip_packet.payload.dstport

                # Update connection tracking data structure
                connection_key = (src_ip, src_port, dst_ip,dst_port)
                if connection_key in self.connections:
                    self.connections[connection_key] += 1
                else:
                    self.connections[connection_key] = 1

                # Calculate dst_host_same_src_port_rate
                same_src_port_connections = sum(1 for key in self.connections.keys() if key[0] == src_ip and key[1] == src_port)
                dst_host_same_src_port_rate = self.connections[connection_key] / same_src_port_connections if same_src_port_connections > 0 else 0
                print("\n\n")
               # print("dst_host_same_src_port_rate: %.2f" % dst_host_same_src_port_rate)
                data['dst_host_same_src_port_rate'].append(dst_host_same_src_port_rate)
                data['destination'].append(dst_ip)
    self.dst_host_srv_count(event)
    self.dst_host_same_srv_rate(event)
    self.src(event)
    self.land(event)
    self.tcp_flags(event)
    self.update_count(event)
    self.wrongfragments(event)
   
    print("\n")

    
  


    
             
    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)


    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)
  
  
  def dst_host_srv_count(self,event):
    packet = event.parsed
    if packet.type == ethernet.IP_TYPE:
        ip_packet = packet.payload
        if isinstance(ip_packet, ipv4):
          src_ip = ip_packet.srcip
          dst_ip = ip_packet.dstip
          if isinstance(ip_packet.payload, tcp):
              dst_port = ip_packet.payload.dstport
              # Update destination host service count
              self.update_dst_host_service_count(dst_ip, dst_port)
                  
  def update_dst_host_service_count(self, dst_ip, dst_port):
        if dst_ip not in self.dst_host_service_count:
            self.dst_host_service_count[dst_ip] = set()
        self.dst_host_service_count[dst_ip].add(dst_port)
        count = len(self.dst_host_service_count[dst_ip])
        #print("Destination host service count: %s -> %d" % (dst_ip, count))
        data['dst_host_srv_count'].append(count)
  
  
  def dst_host_same_srv_rate(self,event):
      packet = event.parsed
      ipv4_packet = packet.find('ipv4')
      tcp_packet = packet.find('tcp')
      if ipv4_packet and tcp_packet:
            dst_ip = ipv4_packet.dstip
            dst_port = tcp_packet.dstport
    
            self.dst_host_connections[dst_ip][dst_port] += 1
    
            total_connections = sum(self.dst_host_connections[dst_ip].values())
            if total_connections > 0:
                same_srv_connections = max(self.dst_host_connections[dst_ip].values())
                dst_host_same_srv_rate = (total_connections - same_srv_connections) / total_connections
                #print("Destination Host Same Service Rate: %.2f" % dst_host_same_srv_rate)
                data['dst_host_same_srv_rate'].append(dst_host_same_srv_rate)
         #   else:
         #       print("No connections for destination IP: %s" % dst_ip)
  
  
  def src(self,event):
  
    packet = event.parsed
    if packet.type == ethernet.IP_TYPE:
                ipv4_packet = packet.find('ipv4')
                if ipv4_packet is not None and ipv4_packet.protocol == ipv4.TCP_PROTOCOL:
                    tcp_packet = ipv4_packet.payload
                    src_bytes = len(tcp_packet.payload)

                #    print("Source Bytes: %d", src_bytes)
                    data['src_bytes'].append(src_bytes)
 
 
 
  def land(self,event):
    
    land = 0
    #packet1=""
    packet = event.parsed
   # print('INCOMING PACKET : ')
    if packet.type == ethernet.IP_TYPE:
        ipv4_packet = packet.find(ipv4)
        if ipv4_packet:
            if ipv4_packet.protocol == ipv4.ICMP_PROTOCOL:
                icmp_packet = packet.find(icmp)
    #            print("ICMP Packet In: Type: %s, Code: %s",icmp_packet.type, icmp_packet.code)
                packet1= 2
               
            elif ipv4_packet.protocol == ipv4.TCP_PROTOCOL:
                tcp_packet = packet.find(tcp)
                packet1= 0
     #           print("TCP Packet In: Src Port: %s, Dst Port: %s",tcp_packet.srcport, tcp_packet.dstport)
                if tcp_packet.srcport == tcp_packet.dstport:
                  land = 1
      #            print('land : ',land)
                
            elif ipv4_packet.protocol == ipv4.UDP_PROTOCOL:
                udp_packet = packet.find(udp)
                packet1= 1
       #         print("UDP Packet In: Src Port: %s, Dst Port: %s",
                     #    udp_packet.srcport, udp_packet.dstport)
                if udp_packet.srcport == udp_packet.dstport:
                  land = 1
        #          print('land : ' , land)
        data['land'].append(land) 
        data['protocol'].append(packet1)  
                    
    elif packet.type == ethernet.IPV6_TYPE:
    	#log.info('This is an ipv6 packet')
       ipv6_packet = packet.find('ipv6')
       if ipv6_packet:
            src_ip = ipv6_packet.srcip
            dst_ip = ipv6_packet.dstip
           # print("SOURCE IP ADDRESS : %s , DESTINATION ADDRESS : %s" ,  src_ip , dst_ip)  
       
                   
                        
  def tcp_flags(self,event):
      packet = event.parsed
      if packet.parsed:
          tcp_pkt = packet.find('tcp')
          if tcp_pkt:
            flags = tcp_pkt.flags
            fin = bool(flags & 0x01)  # FIN
            syn = bool(flags & 0x02)  # SYN
            rst = bool(flags & 0x04)  # RST
            psh = bool(flags & 0x08)  # PSH
            ack = bool(flags & 0x10)  # ACK
            urg = bool(flags & 0x20)  # URG
            
            tcp_flags = {
               10 : not (urg or ack or psh or rst or syn or fin),                     #oth  
                2 : not (ack or rst) and syn,                                         #rej
                5 : rst and not (ack or syn),                                         #rsto
                7 : rst and not (ack or syn or fin),                                  #rstos0
                3 : rst and ack,                                                      #rstr
                1 : syn and not (ack or psh or rst or fin),                           #s0
                6 : syn and ack and not (psh or rst or fin),                          #'s1'
                9 : syn and ack and fin and not (psh or rst),                         #'s2' 
                8 : syn and ack and fin and psh and not rst,                          #s3
                0 : syn and ack and fin and not rst and not psh,                      #sf
                4 : fin and not ack and not rst and not syn and not psh               #sh
            }
            
            tcp_flags_val=[]
            for flag,value in tcp_flags.items():
              if value ==True:
        #          print(f"{flag.upper()}:{value}")
                  tcp_flags_val.append(flag)
            data['tcp_flags'].append(tcp_flags_val[0])

  def update_count(self,event):
   

    packet = event.parsed 
    if packet.type == packet.IP_TYPE:
          ip_packet = packet.find('ipv4')
          if ip_packet.protocol == ip_packet.TCP_PROTOCOL:   
                dst_ip = ip_packet.dstip
                #self.connection_timestamps[dst_ip] = time.time()
                
              
          # Update count for the destination host
                if dst_ip in self.connection_counts:
                    self.connection_counts[dst_ip] += 1
                    
                else:
                    self.connection_counts[dst_ip] = 1

                current_time = time.time()
                
                
                count=self.connection_counts.get(dst_ip)
               # print(self.connection_counts)
               # print("Connection counts:", count)
                data['count'].append(count)
              

  def clearCount(self):
    self.connection_counts = {}
    threading.Timer(2, self.clearCount).start()              
                  

      
  
  def wrongfragments(self,event):
    global aliassajut
    packet = event.parsed
    if packet.type == packet.IP_TYPE:
      ip_packet = packet.find('ipv4')
      if ip_packet and (ip_packet.flags & 0x2000):  # Check if MF flag is set
        #log.info("Received a fragment with the MF flag set: %s" % ip_packet)
        MF=1
       # print("MF",MF)
        data['wrongfragments'].append(MF)
      else:
        #print("Received a non-fragment packet: %s" % ip_packet)
        MF=0
       # print("MF",MF)
        data['wrongfragments'].append(MF)		
  
      global newx,oldx, prevResults
      newx=len(data['land'])
      #print(data)
      if newx>oldx :
          
          oldx=newx
          if oldx %2==0:
            l = [data['protocol'][aliassajut] , data['tcp_flags'][aliassajut] , data['src_bytes'][aliassajut] , data['land'][aliassajut] , data['wrongfragments'][aliassajut] ,data["count"][aliassajut], data['dst_host_same_src_port_rate'][aliassajut], data['dst_host_srv_count'][aliassajut] , data['dst_host_same_srv_rate'][aliassajut]] 
            aliassajut=aliassajut+2
            input_array = np.array(l)
            input_array_reshaped = input_array.reshape(1, 1, -1)
            predictions = model.predict(input_array_reshaped)
            output_array = np.argmax(np.array(predictions))
            prevResults.append(output_array)
            if(len(prevResults) >= 100):
              res = most_frequent(prevResults)
              prevResults = []
              if(res > 0):
                displayAlert({'status': 'malicious'})
            # print('PREDICTED VALUE : ' , output_array)
            # print('\n\n')

def most_frequent(List):
    dict = {}
    count, itm = 0, ''
    for item in reversed(List):
        dict[item] = dict.get(item, 0) + 1
        if dict[item] >= count :
            count, itm = dict[item], item
    return(itm)
 
class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent, ignore = None):
    """
    Initialize

    See LearningSwitch for meaning of 'transparent'
    'ignore' is an optional list/set of DPIDs to ignore
    """
    core.openflow.addListeners(self)
    self.transparent = transparent
    self.ignore = set(ignore) if ignore else ()
    thread1 = threading.Thread(target=main)
    thread1.start()
    

  def _handle_ConnectionUp (self, event):
    if event.dpid in self.ignore:
      log.debug("Ignoring connection %s" % (event.connection,))
      return
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent)
 
  def update_dst_host_service_count(self, dst_ip, dst_port):
        if dst_ip not in self.dst_host_service_count:
            self.dst_host_service_count[dst_ip] = set()
        self.dst_host_service_count[dst_ip].add(dst_port)
        count = len(self.dst_host_service_count[dst_ip])
        log.info("Updated destination host service count: %s -> %d" % (dst_ip, count))
      

 
def launch (transparent=False, hold_down=_flood_delay, ignore = None):
  """
  Starts an L2 learning switch.
  """
  

  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  if ignore:
    ignore = ignore.replace(',', ' ').split()
    ignore = set(str_to_dpid(dpid) for dpid in ignore)

  core.registerNew(l2_learning, str_to_bool(transparent), ignore)

