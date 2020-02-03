# Centralized Virtual Router Redundancy Protocol using a Floodlight Controller

Given a scenario with two subnets. Where, the first one is Network A that is composed of a set of clients and a SDN-enabled switch (SS), which is managed by an SDN controller. Network B is composed of a set of servers and a legacy switch (LS). The two networks are connected by means of two routers.

![alt text](https://github.com/djqwert/centralized-virtual-router-redundancy-with-floodlight-sdn/blob/master/doc/img/net.png)

We defined and implemented a centralized mechanism to let clients in Network A communicate with servers in Network B through one gateway (either R1 or R2) that can be changed dynamically (e.g. due to failures). In particular, at any time only one router (either R1 or R2) must operate as the gateway for all clients, while the other is available as a backup without implementing load balancing. Nonetheless, clients must be unaware of which router is acting as a gateway at all times.
