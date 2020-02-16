package net.floodlightcontroller.project;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActions;
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
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.util.FlowModUtils;

public class VREController implements IFloodlightModule, IOFMessageListener {
	
	protected IFloodlightProviderService floodlightProvider; // Reference to the provider	
	
	private static int[] PRIORITY = new int[] {-1,-1};
	
	// Rule timeouts
	private final static short IDLE_TIMEOUT = Parameters.VREC_IDLE_TIMEOUT; // after a second if a dont receive a packet
	private final static short HARD_TIMEOUT = Parameters.VREC_HARD_TIMEOUT; // never
	private final static int TIMEOUT = Parameters.MASTER_DOWN_INTERVAL;
	private static Timer MASTER_DOWN_TIMER = null;
	TimerTask router_down = null;
	
	private IOFSwitch sw;
	
	private static final Logger logger = LoggerFactory.getLogger(VREController.class);
	
	public class newElection extends TimerTask {
	    
		public void run() {
	        
			logger.info("Advertisement interval has expired... " + Parameters.ROUTER[Parameters.MRID] + " is down");
			handleDisconnection();
	    	
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
		
		if(this.sw == null)
			this.sw = sw;

        // Dissect Packet included in Packet-In
		if(eth.isBroadcast()) {
			
			if(pkt instanceof IPv4) {
				
				IPv4 ip = (IPv4) pkt;
				
				IPv4Address src = ip.getSourceAddress();
				//IPv4Address dest = ip.getDestinationAddress();
				//logger.info("Pre-processing IPv4 packet coming from " + src + " directed to " + dest);
				
				
				if(ip.getProtocol() == IpProtocol.UDP) {
					
					UDP udp = (UDP) ip.getPayload();

					if(udp.getDestinationPort().compareTo(Parameters.PROTO_PORT) == 0) {
							
							if(Parameters.MRID == -1 || (Parameters.MRID != -1 && ip.getSourceAddress().compareTo(Parameters.ROUTER_IP[Parameters.MRID]) != 0)) {
							
								setPriority(sw, src, udp);
								
							} else {
								
								// handle ADV
								getPriority(sw, src, udp);		
								
							}
						
						return Command.STOP;
						
					}
					
				}
			}
		}
		
		return Command.CONTINUE;
		
	}
	
	// Used to send the master's priority as ADV RPY to routers
	private void getPriority(IOFSwitch sw, IPv4Address src, UDP udp) {
		
		Data data = (Data) udp.getPayload();
		
		int id = Integer.parseInt(new String(data.getData()));
		
		if(id == 0) {	// A router can send a disconnection command with a priority value equal to zero
			
			logger.info(Parameters.ROUTER[Parameters.MRID] + " has been disconnected");
			handleDisconnection();			
			
		}else{			// The controller answer generating an ADV RPY for routers
			
			logger.info("Virtual Router Advertisement received");
			handleElection();
			setTimer();
			
		}
		
	}
	
	// Used to set PRIORITY[i] with the priority sent by the router i
	private void setPriority(IOFSwitch sw, IPv4Address src, UDP udp) {
	
		Data data = (Data) udp.getPayload();
		
		int id = Integer.parseInt(new String(data.getData()));
			
		if(src.compareTo(Parameters.ROUTER_IP[0]) == 0)
			PRIORITY[0] = id;
		else
			PRIORITY[1] = id;
	
		logger.info("Priority " + id + " sent from " + src + " has arrived");
		
		election();
		
	}
	
	// Start election phase
	private void election() {
		
		logger.info("Election phase is starting...");
		
		Parameters.MRID = PRIORITY[0] > PRIORITY[1] ? 0 : 1;
		
		if(PRIORITY[0] != -1 && PRIORITY[1] != -1)
			Parameters.BRID = PRIORITY[0] <= PRIORITY[1] ? 0 : 1;
		
		logger.info("Election has been concluded, setting " + Parameters.ROUTER[Parameters.MRID] + " as MASTER!");
		
		if(Parameters.BRID != -1)
			logger.info("Election has been concluded, setting " + Parameters.ROUTER[Parameters.BRID]+ " as BACKUP!");
		
		setTimer();
		handleElection();
		
	}

	// Inform routers with the election result genereting the ELE (ADV RPY) message
	private void handleElection() {
		
		Data data = new Data();
		data.setData(String.valueOf(PRIORITY[Parameters.MRID]).getBytes());
		
		// Creo il pacchetto di risposta per entrambi i router
		IPacket adv = new Ethernet()
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
		
		byte[] packetData = adv.serialize();
		pob.setData(packetData);
		
		sw.write(pob.build());
		
		logger.info("Routers has been informed");
		
	}
	
	private void stopTimer() {
		
		if(MASTER_DOWN_TIMER != null) {
			MASTER_DOWN_TIMER.cancel();
			MASTER_DOWN_TIMER.purge();
		}
		
	}
	
	private void setTimer() {
		
		stopTimer();
		router_down = new newElection();
		MASTER_DOWN_TIMER = new Timer();
		MASTER_DOWN_TIMER.schedule(router_down, TIMEOUT);
		
	}
	
	// Used to delete all flows rules associated to old master router and to install the default flow rule
	private void handleDisconnection(){
		
		// Delete all flow rules
		//OFFlowMod.Builder flow = sw.getOFFactory().buildFlowDeleteStrict();
		OFFlowMod.Builder flow = sw.getOFFactory().buildFlowDelete();
		flow.setBufferId(OFBufferId.NO_BUFFER);
		flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(FlowModUtils.PRIORITY_MAX);
        
        sw.write(flow.build());

        // Add the default flow rule
        flow = sw.getOFFactory().buildFlowAdd();
        
        flow.setIdleTimeout(IDLE_TIMEOUT);
        flow.setHardTimeout(HARD_TIMEOUT);
        flow.setBufferId(OFBufferId.NO_BUFFER);
        flow.setOutPort(OFPort.ANY);
        flow.setCookie(U64.of(0));
        flow.setPriority(0);
        
        ArrayList<OFAction> actionList = new ArrayList<OFAction>();
        
        OFActions actions = sw.getOFFactory().actions();
        
        OFActionOutput output = actions.buildOutput()
    	    .setMaxLen(0xFFffFFff)
    	    .setPort(OFPort.CONTROLLER)
    	    .build();
        actionList.add(output);
        
        flow.setActions(actionList);
        sw.write(flow.build());
        
        // Give the possibility to the Backup Router to become the Master Router, if it is up
        PRIORITY[Parameters.MRID] = -1;
        Parameters.MRID = Parameters.BRID;
		Parameters.BRID = -1;
		
		if(Parameters.MRID != -1)
			election();
		else {
			stopTimer();
			logger.info("No Router has found actived...");
		}
		
	}

}