package net.floodlightcontroller.project;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;

public class ARPController implements IOFMessageListener, IFloodlightModule {
	
	protected IFloodlightProviderService floodlightProvider;
	
	private static final Logger logger = LoggerFactory.getLogger(ARPController.class);

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return ARPController.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		logger.info("ARP Controller is starting...");
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			
			IPacket pkt = eth.getPayload();
			
			// Cast to Packet-In
			OFPacketIn pi = (OFPacketIn) msg;

	        // Dissect Packet included in Packet-In
			if (pkt instanceof ARP) {
					
					// Process ARP request
					handleARPRequest(sw, pi, cntx);
					
					// Interrupt the chain
					return Command.STOP;
				
			}
			
			// Interrupt the chain
			return Command.CONTINUE;
			
	}
	
	private OFPort getSwitchPort(IPv4Address ip) {
		
		if(ip.compareTo(Parameters.HOST_IP[0]) == 0)
			return Parameters.SWITCH_PORT[2];
		
		if(ip.compareTo(Parameters.HOST_IP[1]) == 0)
			return Parameters.SWITCH_PORT[3];
		
		if(ip.compareTo(Parameters.HOST_IP[2]) == 0)
			return Parameters.SWITCH_PORT[4];
		
		if(ip.compareTo(Parameters.ROUTER_IP[0]) == 0)
			return Parameters.SWITCH_PORT[0];
		
		// else if(ip.compareTo(Parameters.ROUTER[1]) == 0)
		return Parameters.SWITCH_PORT[1];
		
	}
	
	private void handleARPRequest(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {

		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpRequest = (ARP) eth.getPayload();
		
		// Devo gestire solo le richieste dirette verso il router
		IPv4Address senderIP = arpRequest.getSenderProtocolAddress();
		IPv4Address targetIP = arpRequest.getTargetProtocolAddress();
		logger.info("Processing ARP packet coming from " + senderIP + " directed to " + targetIP);
		/*if(targetIP.compareTo(Parameters.VRIP) != 0 && targetIP.applyMask(Parameters.NETMASK).compareTo(Parameters.SUBNET) == 0) {
			logger.info("ARP request not modified because the target node is inside the network");
			return;
		}*/
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		IPacket arpReply = null;
		OFActionOutput.Builder actionBuilder = null;
		
		if(targetIP.compareTo(Parameters.VRIP) == 0 && arpRequest.getOpCode().compareTo(ARP.OP_REQUEST) == 0) {
			
			// Generate ARP reply
			arpReply = new Ethernet()		// Il nodo si comporta come se fosse il nodo e rispondesse all'host che gli ha fatto richiesta
				.setSourceMACAddress(Parameters.VRMAC)
				.setDestinationMACAddress(eth.getSourceMACAddress())
				.setEtherType(EthType.ARP)
				.setPriorityCode(eth.getPriorityCode())
				.setPayload(
					new ARP()
					.setHardwareType(ARP.HW_TYPE_ETHERNET)
					.setProtocolType(ARP.PROTO_TYPE_IP)
					.setHardwareAddressLength((byte) 6)
					.setProtocolAddressLength((byte) 4)
					.setOpCode(ARP.OP_REPLY)
					.setSenderHardwareAddress(Parameters.VRMAC) 	// Set my MAC address
					.setSenderProtocolAddress(Parameters.VRIP) 		// Set my IP address
					.setTargetHardwareAddress(arpRequest.getSenderHardwareAddress())	// Setto il MAC dell'host
					.setTargetProtocolAddress(arpRequest.getSenderProtocolAddress()));	// Setto l'ip dell'host che ha fatto richiesta
			
			// Create action -> send the packet back from the source port
			actionBuilder = sw.getOFFactory().actions().buildOutput();
			// The method to retrieve the InPort depends on the protocol version 
			OFPort port = getSwitchPort(arpRequest.getSenderProtocolAddress());
			actionBuilder.setPort(port);
			
		}else {
			
			if(arpRequest.getOpCode().compareTo(ARP.OP_REQUEST) == 0) {
				// richiesta
				
				MacAddress mac = null;
				IPv4Address ip = null;
				if(arpRequest.getSenderProtocolAddress().compareTo(Parameters.ROUTER_IP[0]) == 0 || arpRequest.getSenderProtocolAddress().compareTo(Parameters.ROUTER_IP[1]) == 0) {
					mac = Parameters.VRMAC;
					ip = Parameters.VRIP;
				}else{
					mac = eth.getSourceMACAddress();
					ip = arpRequest.getSenderProtocolAddress();
				}
				
				arpReply = new Ethernet()		// Il nodo si comporta come se fosse il nodo e rispondesse all'host che gli ha fatto richiesta
						.setSourceMACAddress(mac)
						.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
						.setEtherType(EthType.ARP)
						.setPriorityCode(eth.getPriorityCode())
						.setPayload(
							new ARP()
							.setHardwareType(ARP.HW_TYPE_ETHERNET)
							.setProtocolType(ARP.PROTO_TYPE_IP)
							.setHardwareAddressLength((byte) 6)
							.setProtocolAddressLength((byte) 4)
							.setOpCode(ARP.OP_REQUEST)
							.setSenderHardwareAddress(mac) 	// Set my MAC address
							.setSenderProtocolAddress(ip) 		// Set my IP address
							.setTargetHardwareAddress(MacAddress.of("00:00:00:00:00:00"))	// Setto il MAC dell'host
							.setTargetProtocolAddress(arpRequest.getTargetProtocolAddress()));	// Setto l'ip dell'host che ha fatto richiesta
		
			}else {
				
				MacAddress mac = null;
				IPv4Address ip = null;
				if(arpRequest.getTargetProtocolAddress().compareTo(Parameters.VRIP) == 0) {
					mac = Parameters.ROUTER_MAC[1];
					ip = Parameters.ROUTER_IP[1];
					System.out.println("Sono entrato qui");
				}else{
					mac = eth.getDestinationMACAddress();
					ip = arpRequest.getTargetProtocolAddress();
				}
				
				arpReply = new Ethernet()		// Il nodo si comporta come se fosse il nodo e rispondesse all'host che gli ha fatto richiesta
						.setSourceMACAddress(eth.getSourceMACAddress())
						.setDestinationMACAddress(mac)
						.setEtherType(EthType.ARP)
						.setPriorityCode(eth.getPriorityCode())
						.setPayload(
							new ARP()
							.setHardwareType(ARP.HW_TYPE_ETHERNET)
							.setProtocolType(ARP.PROTO_TYPE_IP)
							.setHardwareAddressLength((byte) 6)
							.setProtocolAddressLength((byte) 4)
							.setOpCode(ARP.OP_REPLY)
							.setSenderHardwareAddress(arpRequest.getSenderHardwareAddress()) 	// Set my MAC address
							.setSenderProtocolAddress(arpRequest.getSenderProtocolAddress()) 	// Set my IP address
							.setTargetHardwareAddress(mac)	// Setto il MAC dell'host
							.setTargetProtocolAddress(ip));	// Setto l'ip dell'host che ha fatto richiesta
			}
				
				// Create action -> send the packet back from the source port
				actionBuilder = sw.getOFFactory().actions().buildOutput();
				// The method to retrieve the InPort depends on the protocol version 
				ARP arp = (ARP) arpReply.getPayload();
				OFPort port = getSwitchPort(arp.getTargetProtocolAddress());
				actionBuilder.setPort(port);
			
		}
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = arpReply.serialize();
		pob.setData(packetData);
		
		logger.info("Sending out ARP reply with IP address");
		
		sw.write(pob.build());
		
	}

}