# This protocol to work correctly need a Floodlight controller
# installed and already actived inside the network

import time
import socket  
import select
import netifaces as ni
import sys
import signal

# function useful to handle disconnection
def signal_handler(sig, frame):
        print "\nRouter stopped!"
        sock.sendto(str(0), (BROADCAST_ADDRESS, COMM_PORT))
        print "Floodlight has been informed"
        exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Set of parameters useful for this application.
# The application need 2 informations given in input with the command: python ./router [DATA1] [DATA2]
# DATA1 Is the name of the interface used to communicate with the controller and to send in broadcast the PRIORITY
# DATA2 is used to send a PRIORITY via command line to the router
INTERFACE_NAME = sys.argv[1]
INTERFACE_IP = ni.ifaddresses(INTERFACE_NAME)[ni.AF_INET][0]["addr"]
BROADCAST_ADDRESS = "10.0.2.255"
VRIP = "10.0.2.254"             # vrip used by the router
COMM_PORT = 8888                # communication port used to exchange packet between routers and controller
ROUTER_STATE = 0                # 0: no-state, 1: backup, 2: master
ADVERTISEMENT_INTERVAL = 1      # default ADVERTISEMENT_INTERVAL must be about 1 sec
CTR_DOWN_INTERVAL = 3*ADVERTISEMENT_INTERVAL  # time interval to declare the controller down
VRID = 1
PRIORITY = int(sys.argv[2])     # priority must be beetwen 1-254
sock = None                     # socket

# This function prints the basic informations of the router like interface used to communicate
# With the controller, its address ip and its PRIORITY
def info():

    print "[INFO]"
    print INTERFACE_NAME
    print "\tinet " + INTERFACE_IP + " netmask 255.255.255.0 " + "broadcast " + BROADCAST_ADDRESS
    print "PRIORITY: " + str(PRIORITY)
    
    global sock

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    print "[INFO] Socket created"

    sock.bind(("", COMM_PORT))

    print "[INFO] Socket bound to port %d" %(COMM_PORT)

    sock.sendto(str(PRIORITY), (BROADCAST_ADDRESS, COMM_PORT))
    print "[INFO] Packet sent to %s throught port %s" %(BROADCAST_ADDRESS, COMM_PORT)
    
# The router sent its PRIORITY in broadcast and it waits for the response from the floodlight controller,
# if the router dont receive a packet within 10 seconds, the election will stop
def election():

    global sock, ROUTER_STATE

    try:
        sock.settimeout(10)
        while True:
            data, addr = sock.recvfrom(1024)                # Is the controller on?
            if addr[0] == VRIP:
                break;
    except:
        print "[ERR] Controller is offline"
        sock.close()
        exit(0)

    print "[INFO] Election terminated"

    data = int(data);

    if PRIORITY < data:
        ROUTER_STATE = 1
    else:
        ROUTER_STATE = 2
   
# This function is very useful to empty the queue bounded with the socket
# because, in some cases, some broadcast packet could be spammed on the same router line
def manageQueue():

    global sock

    try:
        sock.setblocking(0)	    # non-blocking mode actived
        while True:
            data, addr = sock.recvfrom(1024)
    except:
        print "[INFO] Receive queue has been emptied"	
        
    sock.setblocking(1)

# Main application function. An active router can jump between the router_state 1 e 2, where
# it is waiting for a master router election or to be downgraded a backup router
def protocol():

    global sock, ROUTER_STATE

    while True:
        
        if ROUTER_STATE == 1:                               # I am waiting for my colleague router goes down
            
            print "[INFO] I am the virtual backup router"
            
            while True:
                
                try:
                    sock.settimeout(CTR_DOWN_INTERVAL)
                    while True:
                        data, addr = sock.recvfrom(1024)    # Is the controller on?
                        if addr[0] == VRIP:
                            break;
                except:
                    print "[ERR] Controller is offline"
                    sock.close()
                    exit(0)
                
                if addr[0] == VRIP and PRIORITY < int(data):
                    print "[INFO] I received the advertisement"
                    continue;
                if addr[0] == VRIP and PRIORITY == int(data):
                    ROUTER_STATE = 2
                    break;
                 
            
        elif ROUTER_STATE == 2:                              # I am the master! Yeah!
            
            print "[INFO] I am the virtual master router"
            
            while True:
            
                sock.sendto(str(PRIORITY), (BROADCAST_ADDRESS, COMM_PORT));
                print "[INFO] VRRP advertisement sent to (%s, %d)" %(BROADCAST_ADDRESS, COMM_PORT)
                
                try:
                    sock.settimeout(CTR_DOWN_INTERVAL)
                    while True:
                        data, addr = sock.recvfrom(1024)    # Is the controller on?
                        if addr[0] == VRIP:
                            break;
                except:
                    print "[ERR] Controller is offline"
                    sock.close()
                    exit(0)
                
                if addr[0] == VRIP and PRIORITY == int(data):
                    print "[INFO] I received the advertisement"
                if addr[0] == VRIP and PRIORITY < int(data):
                    ROUTER_STATE = 1
                    break;
                
                time.sleep(ADVERTISEMENT_INTERVAL)  
            
        else:                                               # OMG, What did it happen here?
                                                            # in general, should must be impossible arrive here
            print "[ERR] Something went wrong during the selection role"
            sock.close()
            exit(-1);

    sock.close()

if __name__ == '__main__':
    
    print "[INFO] Lazy VRRP started on this device"
    
    info()
    election()
    manageQueue()
    protocol()    