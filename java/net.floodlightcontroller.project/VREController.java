package net.floodlightcontroller.project;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

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
import org.projectfloodlight.openflow.types.TransportPort;
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
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.FlowModUtils;

public class VREController implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider	
	
	private static int[] VRID = new int[] {-1,-1};
	
	// Rule timeouts
	private final static short IDLE_TIMEOUT = 1; // after a second if a dont receive a packet
	private final static short HARD_TIMEOUT = 0; // never
	
	protected static Timer timer = null;
	TimerTask task = null;
	
	private IOFSwitch sw;
	
	private static final Logger logger = LoggerFactory.getLogger(VREController.class);
	
	public class newElection extends TimerTask {
	    
		public void run() {
	        
			/* bisogna strutturare le informazioni in array e mantenere l'indice del router master,
			 * a questo punto se il master cade, il backup router diventa il nuovo master
			 */
			logger.info("Advertisement time expired... " + Parameters.ROUTER[Parameters.MRID] + " is down");
			
			VRID[Parameters.MRID] = -1;
			
			Parameters.MRID = Parameters.BRID;
			Parameters.BRID = -1;
			
			if(Parameters.MRID != -1)
				election();
			else
				logger.info("No Router actived...");
	    	
	    }
		
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return VREController.class.getSimpleName();
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
		logger.info("Virtual Router Election controller is starting...");
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			
		IPacket pkt = eth.getPayload();

        // Dissect Packet included in Packet-In
		if (eth.isBroadcast()) {
			
			if (pkt instanceof IPv4) {
				
				IPv4 ip = (IPv4) pkt;
				
				IPv4Address senderIP = ip.getSourceAddress();
				IPv4Address targetIP = ip.getDestinationAddress();
				// logger.info("Pre-processing IPv4 packet coming from " + senderIP + " directed to " + targetIP);

				if(ip.getProtocol() == IpProtocol.UDP) {
					
					UDP udp = (UDP) ip.getPayload();

					if(udp.getDestinationPort().compareTo(Parameters.PROTO_PORT) == 0) {
						
						if(Parameters.MRID != -1) {
							
							if(ip.getSourceAddress().compareTo(Parameters.ROUTER_IP[Parameters.MRID]) != 0) {
							
								handleVRID(sw, msg, udp, senderIP);
								
								// Interrupt the chain
								return Command.STOP;
								
							} else {
								
								handleADV(msg);
								
							} 
							
						}else {
							
							handleVRID(sw, msg, udp, senderIP);
								
						}
						
						return Command.STOP;
						
					}
					
				}
			}
		}
		
		// Interrupt the chain
		return Command.CONTINUE;
		
	}
	
	private void handleADV(OFMessage msg) {
		
		logger.info("Virtual Router Advertisement received");
		
		timer.cancel();
		timer.purge();
		timer = new Timer();
		task = new newElection();
		timer.schedule(task, Parameters.TIMEOUT);
		
		/*Match.Builder mb = sw.getOFFactory().buildMatch();
        mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
        	.setExact(MatchField.IPV4_DST, Parameters.BROADCAST)
        	.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
        	.setExact(MatchField.UDP_DST, Parameters.PROTO_PORT);*/
		
        /* AZIONI */ 
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();      // una action list vuota fa droppare il pacchetto dallo switch
        
        OFActions actions = sw.getOFFactory().actions();
        
        OFOxms oxms = sw.getOFFactory().oxms();

        /*OFActionSetField setDlDst = actions.buildSetField()
        	    .setField(
        	        oxms.buildEthDst()
        	        .setValue(MacAddress.of("ff:ff:ff:ff:ff:ff"))
        	        .build()
        	    )
        	    .build();
        actionList.add(setDlDst);
        
        OFActionSetField setNwDst = actions.buildSetField()
        	    .setField(
        	        oxms.buildIpv4Dst()
        	        .setValue(IPv4Address.of("127.0.0.1"))
        	        .build()
        	    )
        	    .build();
        actionList.add(setNwDst);
        
        OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(OFPort.CONTROLLER)
        	    .build();
        actionList.add(output);*/
        
        /*OFFlowAdd.Builder flow = sw.getOFFactory().buildFlowAdd();
		
        flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ZERO);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);
        
        flow.setActions(actionList);
        flow.setMatch(mb.build());
        
        sw.write(flow.build());*/
        
        OFPacketIn pi = (OFPacketIn) msg;
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(pi.getBufferId());
		pob.setInPort(OFPort.ANY);
		
		OFActionOutput output = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(Parameters.SWITCH_PORT[0])
        	    .build();
        actionList.add(output);
		
		pob.setActions(actionList);
		
		// Packet might be buffered in the switch or encapsulated in Packet-In 
		// If the packet is encapsulated in Packet-In sent it back
		/*if (pi.getBufferId() == OFBufferId.NO_BUFFER) {
			// Packet-In buffer-id is none, the packet is encapsulated -> send it back
            byte[] packetData = pi.getData();
            pob.setData(packetData);
            
		} */
				
		sw.write(pob.build());
		
	}
	
	private void handleVRID(IOFSwitch sw, OFMessage msg, UDP udp, IPv4Address senderIP) {
		
		Data data = (Data) udp.getPayload();
		OFPacketIn pi = (OFPacketIn) msg;
		int id = Integer.parseInt(new String(data.getData()));
			
		if(timer == null) {
			this.sw = sw;
		}
		
		if(senderIP.compareTo(Parameters.ROUTER_IP[0]) == 0)
			VRID[0] = id;
		else
			VRID[1] = id;
	
		logger.info("VRID " + id + " sent from " + senderIP + " has arrived from port " + pi.getMatch().get(MatchField.IN_PORT));
		
		election();
		
	}
	
	private void election() {
		
		logger.info("Election phase is starting...");
		
		Parameters.MRID = VRID[0] > VRID[1] ? 0 : 1;
		
		if(VRID[0] != -1 && VRID[1] != -1)
			Parameters.BRID = VRID[0] <= VRID[1] ? 0 : 1;
		
		logger.info("Election timed out, setting " + Parameters.ROUTER[Parameters.MRID] + " as MASTER!");
		
		if(Parameters.BRID != -1)
			logger.info("Election timed out, setting Router " + Parameters.ROUTER[Parameters.BRID]+ " as BACKUP!");
		
		if(timer != null) {
			timer.cancel();
			timer.purge();
		}
		timer = new Timer();
		task = new newElection();
		timer.schedule(task, Parameters.TIMEOUT);
		
		handleElection();
		
	}

	private void handleElection() {
		
		Data data = new Data();
		data.setData(String.valueOf(VRID[Parameters.MRID]).getBytes());
		
		// Creo il pacchetto di risposta per entrambi i router
		IPacket electionAdvertisement = new Ethernet()
				.setSourceMACAddress(Parameters.VRMAC)
				.setDestinationMACAddress(MacAddress.of("ff:ff:ff:ff:ff:ff"))
				.setEtherType(EthType.IPv4)
				.setPriorityCode((byte) 0)
				.setPayload(
					new IPv4()
					.setProtocol(IpProtocol.UDP)
					.setDestinationAddress(Parameters.BROADCAST)
					.setSourceAddress(Parameters.VRIP)
					.setTtl((byte)64)
					.setProtocol(IpProtocol.IPv4)
					// Set the same payload included in the request
					.setPayload(
							new UDP()
							.setSourcePort(Parameters.PROTO_PORT)
							.setDestinationPort(Parameters.PROTO_PORT)
							.setPayload(data)
					)
					);
		
		// Create the Packet-Out and set basic data for it (buffer id and in port)
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(OFPort.ANY);
	
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        OFActions actions = sw.getOFFactory().actions();
        
        // La risposta viene propagata solamente sulle linee dei due router
        OFActionOutput output1 = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(Parameters.SWITCH_PORT[0])
        	    .build();
        actionList.add(output1);
        OFActionOutput output2 = actions.buildOutput()
        	    .setMaxLen(0xFFffFFff)
        	    .setPort(Parameters.SWITCH_PORT[1])
        	    .build();
        actionList.add(output2);
        
		pob.setActions(actionList);
		
		// Set the ICMP reply as packet data 
		byte[] packetData = electionAdvertisement.serialize();
		pob.setData(packetData);
		
		logger.info("Election phase has been concluded");
		
		sw.write(pob.build());
		
	}

}