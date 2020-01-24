package net.floodlightcontroller.project;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.FlowModUtils;

public class VAController implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider
	
	// Rule timeouts
	private final static short SEND_IDLE_TIMEOUT = Parameters.VAC_SEND_IDLE_TIMEOUT;
	private final static short SEND_HARD_TIMEOUT = Parameters.VAC_SEND_HARD_TIMEOUT;
	private final static short RECV_IDLE_TIMEOUT = Parameters.VAC_RECV_IDLE_TIMEOUT;
	private final static short RECV_HARD_TIMEOUT = Parameters.VAC_RECV_HARD_TIMEOUT;

	private static final Logger logger = LoggerFactory.getLogger(VAController.class);

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return VAController.class.getSimpleName();
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
		// TODO Auto-generated method stub
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
		logger.info("Virtual Addressing Controller is running...");
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
			
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			
			IPacket pkt = eth.getPayload();
			
			OFPacketIn pi = (OFPacketIn) msg;

			if (pkt instanceof IPv4) {
				
				IPv4 ip = (IPv4) pkt;
				
				IPv4Address src = ip.getSourceAddress();
				IPv4Address dest = ip.getDestinationAddress();
				logger.info("Preprocessing IPv4 packet coming from " + src + " directed to " + dest);
				
				if(ip.getDestinationAddress().applyMask(Parameters.NETMASK).compareTo(Parameters.SUBNET) != 0){
					
					handleIPPacket(sw, pi, cntx);
					
					return Command.STOP;
					
				}
			}
			
			return Command.CONTINUE;

	}

	private void handleIPPacket(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {
		
		// Double check that the payload is IPv4
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		IPv4 ipv4 = (IPv4) eth.getPayload();

		if (! (ipv4.getPayload() instanceof ICMP))
			return;
		
		// Devo gestire solo le richieste dirette verso il router
		IPv4Address src = ipv4.getSourceAddress();
		IPv4Address dest = ipv4.getDestinationAddress();
		logger.info("Processing ICMP packet coming from " + src + " directed to " + dest);
		if(dest.compareTo(Parameters.ROUTER_IP[0]) == 0 || dest.compareTo(Parameters.ROUTER_IP[1]) == 0) {
			logger.info("IP message not modified because the sender is a router");
			return;
		}
		
		if(Parameters.MRID != -1) {
		
			sendICMP(sw, pi, cntx, src, dest);
			receiveICMP(sw, pi, cntx, src, dest);
			
		} else {
			
			errorICMP(sw, pi, cntx, src, dest);
			
		}
             
	}
	
	private void sendICMP(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx, IPv4Address src, IPv4Address dest) {
		
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
		
        flow.setIdleTimeout(SEND_IDLE_TIMEOUT);
        flow.setHardTimeout(SEND_HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);

        // Create the match structure  
        Match.Builder match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        	.setExact(MatchField.ETH_DST, Parameters.VRMAC)
        	.setExact(MatchField.IPV4_SRC, src)
        	.setExact(MatchField.IPV4_DST, dest)
        	.setExact(MatchField.IP_PROTO, IpProtocol.ICMP);
        	//.setExact(MatchField.ICMPV4_TYPE, ICMPv4Type.of(ICMP.ECHO_REQUEST));
        
        // Create the actions (Change DST mac and IP addresses and set the out-port)        
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
        OFActions actions = sw.getOFFactory().actions();
        
        OFOxms oxms = sw.getOFFactory().oxms();
        
        OFActionSetField setDlDst = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(Parameters.ROUTER_MAC[Parameters.MRID])
        	        .build()
        	    )
        	    .build();
        actionList.add(setDlDst);
        
        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(Parameters.SWITCH_PORT[Parameters.MRID])
        	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        flow.setMatch(match.build());
        
        sw.write(flow.build());
        
        logger.info("ICMP sending rules written on Floodlight Switch");
        
        // If we do not apply the same action to the packet we have received and we send it back the first packet will be lost
        
 		// Create the Packet-Out and set basic data for it (buffer id and in port)
 		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
 		pob.setBufferId(pi.getBufferId());
 		pob.setInPort(OFPort.ANY);
 		
 		// Assign the action
 		pob.setActions(actionList);
 		
 		// Packet might be buffered in the switch or encapsulated in Packet-In 
 		// If the packet is encapsulated in Packet-In sent it back
 		if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
 			
 			// Packet-In buffer-id is none, the packet is encapsulated -> send it back
             byte[] packetData = pi.getData();
             pob.setData(packetData);
             
 		} 
 				
 		sw.write(pob.build());
 		
 		logger.info("Sending out ICMP packet with IP address " + src + " to " + dest + " throught " + Parameters.ROUTER[Parameters.MRID]);
		
	}
	
	private void receiveICMP(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx, IPv4Address src, IPv4Address dest) {
        
        OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();

        flow.setIdleTimeout(RECV_IDLE_TIMEOUT);
        flow.setHardTimeout(RECV_HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);

        Match.Builder match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.IPv4)
    	.setExact(MatchField.IPV4_DST, src)
        .setExact(MatchField.IP_PROTO, IpProtocol.ICMP);
        
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
        OFActions actions = sw.getOFFactory().actions();
        
        OFOxms oxms = sw.getOFFactory().oxms();
        
        OFActionSetField setDlDstRev = actions.buildSetField()
    	    .setField(
    	        oxms.buildEthSrc()
    	        .setValue(Parameters.VRMAC)
    	        .build()
    	    )
    	    .build();
        actionList.add(setDlDstRev);
        
        OFActionOutput output = actions.buildOutput()
    	    .setMaxLen(0xFFffFFff)
    	    .setPort(pi.getMatch().get(MatchField.IN_PORT))
    	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        flow.setMatch(match.build());
        
        sw.write(flow.build());
        
        logger.info("ICMP receving rules written on Floodlight Switch");
		
	}

	private void errorICMP(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, IPv4Address src, IPv4Address dest) {
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();

		// Cast to ICMP packet
		ICMP icmpRequest = (ICMP) ipv4.getPayload();
			
		// Generate ICMP reply
		IPacket reply = new Ethernet()
			.setSourceMACAddress(Parameters.VRMAC)
			.setDestinationMACAddress(eth.getSourceMACAddress())
			.setEtherType(EthType.IPv4)
			.setPriorityCode(eth.getPriorityCode())
			.setPayload(
				new IPv4()
				.setProtocol(IpProtocol.ICMP)
				.setDestinationAddress(ipv4.getSourceAddress())
				.setSourceAddress(Parameters.VRIP)
				.setTtl((byte)64)
				.setProtocol(IpProtocol.IPv4)
				// Set the same payload included in the request
				.setPayload(
						new ICMP()
						.setIcmpType(ICMP.DESTINATION_UNREACHABLE)
						.setIcmpCode(ICMP.CODE_PORT_UNREACHABLE)
                        .setPayload(icmpRequest.getPayload())
				)
				);
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		// Create action -> send the packet back from the source port
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput();
		// The method to retrieve the InPort depends on the protocol version 
		OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
		actionBuilder.setPort(inPort); 
		
		// Assign the action
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ICMP reply as packet data 
		byte[] packetData = reply.serialize();
		pob.setData(packetData);
		
		sw.write(pob.build());
		
		logger.info("Master Router is down. ICMP error has sent back to " + src);
		
	}
	
}