# This protocol to work correctly need a Floodlight controller
# installed and already actived inside the network

from random import random
import time
import socket  
import select
import netifaces as ni
import sys

# potremmo eventualmente creare una seconda socket 

''' Set of parameters '''
INTERFACE_NAME = sys.argv[1] + "-eth1"
INTERFACE_IP = ni.ifaddresses(INTERFACE_NAME)[ni.AF_INET][0]["addr"]
BROADCAST_ADDRESS = "10.0.2.255"
COMM_PORT = 8888
ROUTER_STATE = 0        # 0: no-state, 1: backup, 2: master
WAITING_TIME = 3.0        # in real cases WAITING_TIME must be about 1 ms (0.001)
VRID = int(sys.argv[2]) # router id must be beetwen 1-255

''' Start configuration '''
print "[INFO]"
print INTERFACE_NAME
print "\tinet " + INTERFACE_IP + " netmask 255.255.255.0 " + "broadcast " + BROADCAST_ADDRESS
print "VRID: " + str(VRID)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

print "[INFO] Socket created"

sock.bind(("", COMM_PORT))

print "[INFO] Socket bound to port %d" %(COMM_PORT)

sock.sendto(str(VRID), (BROADCAST_ADDRESS, COMM_PORT))
print "[INFO] Packet sent to %s throught port %s" %(BROADCAST_ADDRESS, COMM_PORT)

''' Router selection '''
try:
    sock.settimeout(4)
    while True:
        data, addr = sock.recvfrom(1024)    # verifico che gli altri nodi siano attivi
        if addr[0] != INTERFACE_IP and addr[0] != BROADCAST_ADDRESS:
            break;
except:
    print "[WARN] I am the only router up"
    sock.sendto(str(0), (BROADCAST_ADDRESS, COMM_PORT))
finally:
    sock.settimeout(None)

print "[INFO] Election terminated"

data = int(data);

if VRID < data:
    ROUTER_STATE = 1
else:
    ROUTER_STATE = 2
    
''' Queue must be empty '''
try:
    sock.setblocking(0)	    # non-blocking mode actived
    while True:
        data, addr = sock.recvfrom(1024)
except:
    print "[INFO] Receive queue has been emptied"	
    
sock.setblocking(1)

''' Main program '''
while True:
    
    if ROUTER_STATE == 1:                       # I am waiting for my colleague router goes down
        
        print "[INFO] I am the virtual backup router"
        print "VRID: ", VRID

        sock.setblocking(1)
        
        while True:
            data, addr = sock.recvfrom(1024) 
            if VRID == int(data) and addr[0] != INTERFACE_IP:
                ROUTER_STATE = 2
                break;
        
    if ROUTER_STATE == 2:                       # I am the master! Yeah!
        
        print "[INFO] I am the virtual master router"
        sock.setblocking(0)
        
        while True:
        
            sock.sendto(str(VRID), (BROADCAST_ADDRESS, COMM_PORT));
            print "[INFO] VRRP advertisement sent to (%s, %d)" %(BROADCAST_ADDRESS, COMM_PORT)
            print "VRID: ", VRID
            
            time.sleep(WAITING_TIME)
            data, addr = sock.recvfrom(1024)
            if VRID < int(data):
                ROUTER_STATE = 1
                break;
            
        
    else:                                       # OMG, What did it happen here?
    
        print "[ERR] Something went wrong during the selection role"
        sock.close()
        exit();

sock.close()