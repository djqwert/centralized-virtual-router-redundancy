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
import org.projectfloodlight.openflow.types.MacAddress;
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
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.FlowModUtils;

public class VirtualAddress implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider
	
	// Rule timeouts
	private final static short IDLE_TIMEOUT = 0;
	private final static short HARD_TIMEOUT = 1;

	private static final Logger logger = LoggerFactory.getLogger(VirtualAddress.class);

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return VirtualAddress.class.getSimpleName();
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
		logger.info("VirtualAddress is starting...");
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
			
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			
			IPacket pkt = eth.getPayload();

			// Print the source MAC address
			Long sourceMACHash = Ethernet.toLong(eth.getSourceMACAddress().getBytes());
			//System.out.printf("MAC Address: {%s} seen on switch: {%s}\n", HexString.toHexString(sourceMACHash), sw.getId());
			
			// Cast to Packet-In
			OFPacketIn pi = (OFPacketIn) msg;

	        // Dissect Packet included in Packet-In
			if (pkt instanceof IPv4) {
				
				IPv4 ip_pkt = (IPv4) pkt;
				
				IPv4Address senderIP = ip_pkt.getSourceAddress();
				IPv4Address targetIP = ip_pkt.getDestinationAddress();
				logger.info("Preprocessing IPv4 packet coming from " + senderIP + " directed to " + targetIP);
				
				if(ip_pkt.getDestinationAddress().applyMask(Parameters.NETMASK).compareTo(Parameters.SUBNET) != 0){
					
					if(Parameters.MRID == -1) 
						handleIPErrPacket(sw, pi, cntx);
					else
						handleIPPacket(sw, pi, cntx);
					
					// Interrupt the chain
					return Command.STOP;
				}
			}
			
			// Interrupt the chain
			return Command.CONTINUE;

	}

	private void handleIPPacket(IOFSwitch sw, OFPacketIn pi,
			FloodlightContext cntx) {
		
		// Double check that the payload is IPv4
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();

		// Check that the IP is actually an ICMP request
		if (! (ipv4.getPayload() instanceof ICMP))
			return;
		
		// Devo gestire solo le richieste dirette verso il router
		IPv4Address senderIP = ipv4.getSourceAddress();
		IPv4Address targetIP = ipv4.getDestinationAddress();
		logger.info("Processing IPv4 packet coming from " + senderIP + " directed to " + targetIP);
		if(targetIP.compareTo(Parameters.ROUTER_IP[0]) == 0 || targetIP.compareTo(Parameters.ROUTER_IP[1]) == 0) {
			logger.info("IP message not modified because the sender is a router");
			return;
		}
		
		// SEND
		
		// Create a flow table modification message to add a rule
		OFFlowAdd.Builder fmb = sw.getOFFactory().buildFlowAdd();
		
        fmb.setIdleTimeout(IDLE_TIMEOUT);
        fmb.setHardTimeout(HARD_TIMEOUT);
        fmb.setBufferId(OFBufferId.NO_BUFFER);
        fmb.setOutPort(OFPort.ANY);
        fmb.setCookie(U64.of(0));
        fmb.setPriority(FlowModUtils.PRIORITY_MAX - 1);

        // Create the match structure  
        Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        	.setExact(MatchField.ETH_DST, Parameters.VRMAC);
        
        // Create the actions (Change DST mac and IP addresses and set the out-port)
        OFActions actions = sw.getOFFactory().actions();
        
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
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
        
        fmb.setActions(actionList);
        fmb.setMatch(mb.build());
        
        sw.write(fmb.build());
        
        /////////////////// RECEIVER
        
        
        OFFlowAdd.Builder fmbRev = sw.getOFFactory().buildFlowAdd();

        fmbRev.setIdleTimeout(IDLE_TIMEOUT);
		fmbRev.setHardTimeout(HARD_TIMEOUT);
		fmbRev.setBufferId(OFBufferId.NO_BUFFER);
		fmbRev.setOutPort(OFPort.CONTROLLER);
		fmbRev.setCookie(U64.of(0));
		fmbRev.setPriority(FlowModUtils.PRIORITY_MAX - 1);

        Match.Builder mbRev = sw.getOFFactory().buildMatch();
        mbRev.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        .setExact(MatchField.IP_PROTO, IpProtocol.ICMP);
        
        ArrayList<OFAction> actionListRev = new ArrayList<OFAction>();
        
        OFActionSetField setDlDstRev = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthSrc()
        	        .setValue(Parameters.VRMAC)
        	        .build()
        	    )
        	    .build();
        actionListRev.add(setDlDstRev);
        
        OFActionOutput outputRev = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(pi.getMatch().get(MatchField.IN_PORT))
        	    .build();
        actionListRev.add(outputRev);
        
        fmbRev.setActions(actionListRev);
        fmbRev.setMatch(mbRev.build());
        
        sw.write(fmbRev.build());

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
		
		logger.info("Sending out IP reply with IP address " + senderIP + " to " + targetIP + " throught " + Parameters.ROUTER[Parameters.MRID]);
             
	}

	private void handleIPErrPacket(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		
		// Double check that the payload is IPv4
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (! (eth.getPayload() instanceof IPv4))
			return;
		
		// Cast the IP packet
		IPv4 ipv4 = (IPv4) eth.getPayload();

		// Check that the IP is actually an ICMP request
		if (! (ipv4.getPayload() instanceof ICMP))
			return;

		// Cast to ICMP packet
		ICMP icmpRequest = (ICMP) ipv4.getPayload();
			
		// Generate ICMP reply
		IPacket icmpReply = new Ethernet()
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
						.setIcmpCode(icmpRequest.getIcmpCode())
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
		byte[] packetData = icmpReply.serialize();
		pob.setData(packetData);
		
		sw.write(pob.build());
		
		logger.info("No route available because the Master Router is down");
		
	}
	
}