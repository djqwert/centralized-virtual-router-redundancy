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
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.util.FlowModUtils;

public class ARPController implements IOFMessageListener, IFloodlightModule {
	
	protected IFloodlightProviderService floodlightProvider;
	
	public final static int IDLE_TIMEOUT = Parameters.ARPC_IDLE_TIMEOUT;
	public final static int HARD_TIMEOUT = Parameters.ARPC_HARD_TIMEOUT;
	
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
		if ((eth.isBroadcast() || eth.isMulticast()) && pkt instanceof ARP) {
			
			ARP arp = (ARP) eth.getPayload();
			
			if(arp.getTargetProtocolAddress().compareTo(Parameters.VRIP) == 0)
				handleVirtualRequest(sw, pi, cntx);
			else
				handleBroadcastRequest(sw, pi, cntx);
				
			return Command.STOP;
			
		}
		
		// Interrupt the chain
		return Command.CONTINUE;
			
	}
	
	private void handleVirtualRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arp = (ARP) eth.getPayload();
		
		// Devo gestire solo le richieste dirette verso il router
		IPv4Address src = arp.getSenderProtocolAddress();
		IPv4Address dest = arp.getTargetProtocolAddress();
		logger.info("Managing Virtual ARP Request");
		
		IPacket arpReply = new Ethernet()		// Il nodo si comporta come se fosse il nodo e rispondesse all'host che gli ha fatto richiesta
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
					.setTargetHardwareAddress(arp.getSenderHardwareAddress())	// Setto il MAC dell'host
					.setTargetProtocolAddress(arp.getSenderProtocolAddress()));	// Setto l'ip dell'host che ha fatto richiesta
			
		// Create action -> send the packet back from the source port
		OFActionOutput.Builder actionBuilder = sw.getOFFactory().actions().buildOutput().setPort(pi.getMatch().get(MatchField.IN_PORT));
		
		// Assign the action
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
 		pob.setBufferId(pi.getBufferId());
 		pob.setInPort(OFPort.ANY);
		pob.setActions(Collections.singletonList((OFAction) actionBuilder.build()));
		
		// Set the ARP reply as packet data 
		byte[] packetData = arpReply.serialize();
		pob.setData(packetData);
		
		logger.info("Sending out ARP reply to destination");
		
		sw.write(pob.build());
		
		// Virtual Flow Rule
		/*OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();

		flow.setIdleTimeout(IDLE_TIMEOUT);
		flow.setHardTimeout(HARD_TIMEOUT);
		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
		flow.setCookie(U64.of(0));
		flow.setPriority(FlowModUtils.PRIORITY_MAX);
		
		Match.Builder match = sw.getOFFactory().buildMatch();
		match.setExact(MatchField.ETH_TYPE, EthType.ARP)
		 	.setExact(MatchField.ETH_DST, MacAddress.of("ff:ff:ff:ff:ff:ff"))
		 	.setExact(MatchField.ARP_TPA, Parameters.VRIP);
		
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		
		OFActions actions = sw.getOFFactory().actions();
		
		OFOxms oxms = sw.getOFFactory().oxms();*/
		
		/*OFActionSetField action1 = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(eth.getSourceMACAddress())
        	        .build()
        	    ).build();
        actionList.add(action1);
        OFActionSetField action2 = actions.buildSetField()
        	    .setField(
        	    	oxms.buildEthSrc()
        	    	.setValue(Parameters.VRMAC)
        	    	.build()
        	    ).build();
        actionList.add(action2);
        OFActionSetField action3 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpOp()
    	    		.setValue(ARP.OP_REPLY)
    	    		.build()
        	    ).build();
        actionList.add(action3);*
        OFActionSetField action4 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpSha()
    	    		.setValue(Parameters.VRMAC)
    	    		.build()
            	 ).build();
        actionList.add(action4);
        OFActionSetField action5 = actions.buildSetField()  
        	    .setField(
    	    		oxms.buildArpTha()
    	    		.setValue(arp.getSenderHardwareAddress())
    	    		.build()
            	 ).build();
        actionList.add(action5);
        OFActionSetField action6 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpSpa()
    	    		.setValue(Parameters.VRIP)
    	    		.build()
            	 ).build();
        actionList.add(action6);
        OFActionSetField action7 = actions.setField(
    	    		oxms.arpTpa(arp.getSenderProtocolAddress()));
        actionList.add(action7);*/
        
        /*OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(pi.getMatch().get(MatchField.IN_PORT))
        	    .build();
        actionList.add(output);*/
		
		/*actionList.add(actions.output(OFPort.LOCAL, Integer.MAX_VALUE));
		actionList.add(actions.setField(oxms.arpOp(ARP.OP_REPLY)));
		actionList.add(actions.setField(oxms.arpSha(MacAddress.BROADCAST)));
		actionList.add(actions.setField(oxms.arpTha(MacAddress.BROADCAST)));
		actionList.add(actions.setField(oxms.arpSpa(IPv4Address.of("255.255.255.255"))));
		actionList.add(actions.setField(oxms.arpTpa(IPv4Address.of("255.255.255.255")))); */
	
		/*flow.setActions(actionList);
		flow.setMatch(match.build());
		 
		if(sw.write(flow.build()))
			logger.info("Virtual Flow Rule written on the Floodlight Switch");
		else
			logger.info("Virtual Flow Rule didn't write on the Floodlight Switch");
	    
	    OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(pi.getBufferId());
		pob.setInPort(OFPort.ANY);
		pob.setActions(actionList);
				
		if(sw.write(pob.build()))
			logger.info("Packet retrasmitted correctly");
		else
			logger.info("Packet didn't retrasmit correctly");*/
		
	}
	
	private void handleBroadcastRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		
		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arp = (ARP) eth.getPayload();
		
		logger.info("Managing Broadcast ARP Request");
		
		// Regole per ARP
		// Broadcast Flow Rule
		OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
		
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		
		OFActions actions = sw.getOFFactory().actions();
		
		OFOxms oxms = sw.getOFFactory().oxms();
		
        flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX - 1);
        
        Match.Builder match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.ARP)
        	.setExact(MatchField.ETH_DST, MacAddress.of("ff:ff:ff:ff:ff:ff"));
        
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
        	    .setPort(OFPort.ALL)
        	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        flow.setMatch(match.build());
        
        if(sw.write(flow.build()))
        	logger.info("Broadcast Flow Rule written on the Floodlight Switch");
        else
        	logger.info("Broadcast Flow Rule didn't write on the Floodlight Switch");
        
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(pi.getBufferId());
		pob.setInPort(OFPort.ANY);
		pob.setActions(actionList);
 				
 		if(sw.write(pob.build()))
 			logger.info("Packet retrasmitted correctly");
 		else
 			logger.info("Packet didn't retrasmit correctly");
 		
 		ArrayList<OFAction> actionList1 = new ArrayList<OFAction>();
 		
 		flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);
        
        match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.ARP)
        	.setExact(MatchField.ETH_DST, MacAddress.of("ff:ff:ff:ff:ff:ff"))
        	.setExact(MatchField.ARP_TPA, Parameters.VRIP);
        
        output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(OFPort.CONTROLLER)
        	    .build();
        actionList1.add(output);
        
        flow.setActions(actionList1);
        flow.setMatch(match.build());
        
        if(sw.write(flow.build()))
        	logger.info("Virtual Flow Rule written on the Floodlight Switch");
        else
        	logger.info("Virtual Flow Rule didn't write on the Floodlight Switch");
		
	}
	
	private void handleARPRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {

		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if (! (eth.getPayload() instanceof ARP))
			return;
		
		// Cast the ARP request
		ARP arpRequest = (ARP) eth.getPayload();
		
		// Devo gestire solo le richieste dirette verso il router
		IPv4Address src = arpRequest.getSenderProtocolAddress();
		IPv4Address dest = arpRequest.getTargetProtocolAddress();
		logger.info("Processing ARP packet coming from " + src + " directed to " + dest);
		/*if(dest.compareTo(Parameters.VRIP) != 0 && targetIP.applyMask(Parameters.NETMASK).compareTo(Parameters.SUBNET) == 0) {
			logger.info("ARP request not modified because the target node is inside the network");
			return;
		}*/
		
		
		/*OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
		
		// Regole per ARP -> Da nodo a Floodlight switch e risposta
        flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);
        
        // Create the match structure  
        Match.Builder match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.ARP)
        	.setExact(MatchField.ETH_DST, MacAddress.of("ff:ff:ff:ff:ff:ff"))
        	.setExact(MatchField.ARP_SPA, src)
        	.setExact(MatchField.ARP_TPA, Parameters.VRIP);
        
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
        OFActions actions = sw.getOFFactory().actions();
        
        OFOxms oxms = sw.getOFFactory().oxms();
        
        OFActionSetField subrule1 = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(eth.getSourceMACAddress())
        	        .build()
        	    )
        	    .build();
        actionList.add(subrule1);
        OFActionSetField subrule2 = actions.buildSetField()
        	    .setField(
        	    	oxms.buildEthSrc()
        	    	.setValue(Parameters.VRMAC)
        	    	.build()
        	    ).build().s
        	    .setField(
        	    		oxms.buildArpOp()
        	    		.setValue(ARP.OP_REPLY)
        	    		.build()
            	    )
	    .build();
        actionList.add(subrule2);
        /*OFActionSetField subrule3 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpOp()
    	    		.setValue(ARP.OP_REPLY)
    	    		.build()
        	    )
	    .build();
        actionList.add(subrule3);*/
        /*OFActionSetField subrule4 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpSha()
    	    		.setValue(Parameters.VRMAC)
    	    		.build()
            	 )
	    .build();
        actionList.add(subrule4);*/
        /*OFActionSetField subrule5 = actions.buildSetField()  
        	    .setField(
    	    		oxms.buildArpTha()
    	    		.setValue(arpRequest.getSenderHardwareAddress())
    	    		.build()
            	 )
	    .build();
        actionList.add(subrule5);*/
        /*OFActionSetField subrule6 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpSpa()
    	    		.setValue(Parameters.VRIP)
    	    		.build()
            	 )
	    .build();
        actionList.add(subrule6);*/
        /*OFActionSetField subrule7 = actions.buildSetField()
        	    .setField(
    	    		oxms.buildArpTpa()
    	    		.setValue(arpRequest.getSenderProtocolAddress())
    	    		.build()
            	 )
        .build();
        actionList.add(subrule7);*/
        
        /*OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(pi.getMatch().get(MatchField.IN_PORT))
        	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        flow.setMatch(match.build());
        
        sw.write(flow.build());
        
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
 		pob.setBufferId(pi.getBufferId());
 		pob.setInPort(OFPort.ANY);
 		
 		// Assign the action
 		pob.setActions(actionList);
 				
 		sw.write(pob.build());
 		
 		return;*/
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		/*pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
		
		IPacket arpReply = null;
		OFActionOutput.Builder actionBuilder = null;
		
		if(dest.compareTo(Parameters.VRIP) == 0 && arpRequest.getOpCode().compareTo(ARP.OP_REQUEST) == 0) {
			
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
		
		logger.info("Sending out ARP reply to destination");
		
		sw.write(pob.build());*/
		
	}

}