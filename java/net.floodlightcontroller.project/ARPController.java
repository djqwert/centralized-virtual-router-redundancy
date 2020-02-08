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
import org.projectfloodlight.openflow.protocol.action.OFActions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
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
		if ((eth.isBroadcast() || eth.isMulticast() || eth.getDestinationMACAddress().compareTo(Parameters.VRMAC) == 0) && pkt instanceof ARP) {
			
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
		// IPv4Address src = arp.getSenderProtocolAddress();
		// IPv4Address dest = arp.getTargetProtocolAddress();
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
		
	}
	
	private void handleBroadcastRequest(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		
		// Double check that the payload is ARP
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		
		if(!(eth.getPayload() instanceof ARP))
			return;
				
		logger.info("Managing Broadcast ARP Request");
		
		// Regole per ARP
		addBroadcastFlowRule(sw, pi);
        addVirtualFlowRule(sw);
        
	}
	
	private void addBroadcastFlowRule(IOFSwitch sw, OFPacketIn pi) {
		
		OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
		
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		
		OFActions actions = sw.getOFFactory().actions();
				
        flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX - 1);
        
        Match.Builder match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.ARP)
        	.setExact(MatchField.ETH_DST, MacAddress.of("ff:ff:ff:ff:ff:ff"));

        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(OFPort.ALL)
        	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        flow.setMatch(match.build());
        
        sw.write(flow.build());
        
        logger.info("Broadcast Flow Rule written on the Floodlight Switch");
        
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(pi.getBufferId());
		pob.setInPort(OFPort.ANY);
		pob.setActions(actionList);
 				
 		sw.write(pob.build());
 		
 		logger.info("Packet retrasmitted correctly");
 		
	}
	
	private void addVirtualFlowRule(IOFSwitch sw) {
		
		OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
		
		ArrayList<OFAction> actionList = new ArrayList<OFAction>();
		
		OFActions actions = sw.getOFFactory().actions();
		
		flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);
        
        Match.Builder match = sw.getOFFactory().buildMatch();
        match = sw.getOFFactory().buildMatch();
        match.setExact(MatchField.ETH_TYPE, EthType.ARP)
        	.setExact(MatchField.ETH_DST, MacAddress.of("ff:ff:ff:ff:ff:ff"))
        	.setExact(MatchField.ARP_TPA, Parameters.VRIP);
        
        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(OFPort.CONTROLLER)
        	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        flow.setMatch(match.build());
        
        sw.write(flow.build());
        	
        logger.info("Virtual Flow Rule written on the Floodlight Switch");
		
	}

}