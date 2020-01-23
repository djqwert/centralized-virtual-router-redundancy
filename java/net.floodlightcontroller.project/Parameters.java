package net.floodlightcontroller.project;

import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

public class Parameters {
	
	public final static IPv4Address SUBNET = IPv4Address.of("10.0.2.0");
	public final static IPv4Address NETMASK = IPv4Address.of("255.255.255.0");
	public final static IPv4Address BROADCAST = IPv4Address.of("10.0.2.255");
	
	public final static IPv4Address VRIP = IPv4Address.of("10.0.2.254");
	public final static MacAddress VRMAC = MacAddress.of("00:00:E5:00:01:01");
	
	final static String[] ROUTER = {
			"Router 1",
			"Router 2"
	};
	
	final static MacAddress[] ROUTER_MAC = {
			MacAddress.of("00:00:00:00:00:01"),
			MacAddress.of("00:00:00:00:00:02")
	};
		
	final static IPv4Address[] ROUTER_IP = {
			IPv4Address.of("10.0.2.1"),
			IPv4Address.of("10.0.2.2")
	};
	
	final static IPv4Address[] HOST_IP = {
			IPv4Address.of("10.0.2.3"),
			IPv4Address.of("10.0.2.4"),
			IPv4Address.of("10.0.2.5")
	};
		
	final static OFPort[] SWITCH_PORT = {
			OFPort.of(4),
			OFPort.of(5),
			OFPort.of(1),
			OFPort.of(2),
			OFPort.of(3)			
	};
	
	public final static TransportPort PROTO_PORT = TransportPort.of(8888);
	
	public static int MRID = -1;
	public static int BRID = -1;
	public static int TIMEOUT = 1500; // expressed in seconds (1000 = 1 sec)
	
}