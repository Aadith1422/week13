# Network Layer of the OSI Model

The **Network Layer (Layer 3)** is the third layer in the OSI model.  
It is responsible for **logical addressing, routing, and packet forwarding** between devices across different networks. Unlike the Data Link Layer, which deals with communication within the same network segment, the Network Layer ensures that data can travel from the **source host to the destination host**, even if they are separated by multiple routers and networks.

This layer essentially **determines how data is delivered across internetworks** and handles addressing, routing, and error reporting.

---

## Functionalities of the Network Layer

1. **Logical Addressing**
   - Assigns **unique logical addresses (IP addresses)** to each device.  
   - Enables identification of hosts across networks.  
   - Example: IPv4 uses a 32-bit address, IPv6 uses 128-bit addresses.

2. **Routing**
   - Determines the **best path** for packets to reach the destination.  
   - Can be static (manually configured) or dynamic (using routing protocols like OSPF, BGP).  
   - Example: Data from a user in India to a server in the USA traverses multiple routers across networks.

3. **Packet Forwarding**
   - Sends packets from source to destination based on IP addresses.  
   - Routers examine the destination IP and forward packets accordingly.

4. **Fragmentation & Reassembly**
   - Large packets may need to be fragmented to fit smaller Maximum Transmission Units (MTUs).  
   - The Network Layer ensures fragmented packets are **reassembled correctly** at the destination.

5. **Error Handling & Diagnostics**
   - Uses protocols like **ICMP (Internet Control Message Protocol)** to report unreachable hosts, network congestion, or routing errors.  
   - Example: The `ping` command uses ICMP to check connectivity.

6. **Traffic Control & Quality of Service (QoS)**
   - Helps manage network congestion.  
   - Prioritizes critical data packets over less important ones.  
   - Example: VoIP traffic may be prioritized over email.

---

## Sublayers of the Network Layer

While the OSI model does not explicitly define sublayers for Layer 3, in practice, the Network Layer can be divided into:

1. **Data Plane (Forwarding Plane)**
   - Responsible for the **actual forwarding of packets** from one interface to another.  
   - Implements **fast packet switching, filtering, and lookup operations**.  

2. **Control Plane**
   - Responsible for **making routing decisions**.  
   - Runs routing protocols such as **RIP, OSPF, BGP, and EIGRP**.  
   - Updates the routing tables used by the Data Plane.

---

## Devices Operating at the Network Layer

- **Routers**
  - Primary devices that **route packets between networks** based on IP addresses.  
  - Maintain routing tables and perform packet forwarding.  

- **Layer 3 Switches**
  - Can perform both **switching within LANs** and **routing between VLANs**.  

- **Firewalls**
  - Operate at Layer 3 to **filter traffic based on IP addresses** and packet headers.  

- **Gateways**
  - Connect **different network protocols or architectures**, converting packet formats when needed.  

---

## Protocols at the Network Layer

- **IP (Internet Protocol)**
  - IPv4: 32-bit addressing, widely used.  
  - IPv6: 128-bit addressing, solves IPv4 exhaustion and improves security.  

- **ICMP (Internet Control Message Protocol)**
  - Used for error reporting and diagnostics.  
  - Examples: `ping`, `traceroute`.  

- **IGMP (Internet Group Management Protocol)**
  - Manages multicast group memberships for routers.  

- **Routing Protocols**
  - **RIP (Routing Information Protocol):** Simple distance-vector protocol.  
  - **OSPF (Open Shortest Path First):** Link-state protocol for fast convergence.  
  - **BGP (Border Gateway Protocol):** Used for inter-domain routing on the internet.  
  - **EIGRP (Enhanced Interior Gateway Routing Protocol):** Cisco proprietary hybrid routing protocol.  

---

## Attacks at the Network Layer

1. **IP Spoofing**
   - Attacker forges source IP to impersonate a trusted device.  
   - Used in DoS attacks or bypassing security filters.

2. **ICMP Flooding / Ping of Death**
   - Attacker sends excessive ICMP requests to overwhelm the target system.  
   - Can lead to network congestion or system crashes.

3. **Smurf Attack**
   - ICMP broadcast amplification attack.  
   - Attacker sends spoofed requests to a network broadcast address, amplifying traffic toward the victim.

4. **Fragmentation Attacks**
   - Manipulate packet fragments to bypass firewalls or cause buffer overflow.  

5. **Routing Attacks**
   - **Route Injection / Hijacking:** Attacker inserts malicious routes into routing tables.  
   - **Blackhole Attack:** Dropping packets at a compromised router to disrupt traffic.  

6. **Man-in-the-Middle (MITM)**
   - Intercepts traffic between source and destination by compromising Layer 3 devices or routing.  

---

## Mitigation Techniques

1. **Packet Filtering**
   - Firewalls and ACLs can block malicious traffic based on IP addresses or protocols.

2. **Ingress & Egress Filtering**
   - Prevents **IP spoofing** by filtering packets with invalid source addresses.

3. **ICMP Rate Limiting**
   - Controls the number of ICMP requests to prevent flooding attacks.

4. **Routing Security**
   - Secure routing protocols with authentication (e.g., OSPF with MD5 signatures).  
   - Monitor routing tables for anomalies.  

5. **VPNs & Encryption**
   - Encrypt data traffic to prevent interception.  
   - Example: IPSec VPN tunnels secure communication over public networks.

6. **IDS/IPS Deployment**
   - Detects suspicious Layer 3 traffic patterns and blocks attacks in real time.  

7. **Network Segmentation**
   - Isolates networks to reduce the attack surface and contain potential breaches.  

8. **Redundant Paths & Load Balancing**
   - Ensures reliability and prevents single points of failure in case of network attacks.

---

## Real-World Example

- A corporate office has multiple branches across cities.  
- **Routers** connect these branches using **IP-based WAN links**.  
- **OSPF** dynamically updates routing tables for optimal paths.  
- An attacker tries **IP spoofing** to gain access to sensitive data.  
- Mitigation: **Ingress filtering, VPN encryption, and IDS monitoring** prevent unauthorized access and data interception.

---

## ✅ Summary

The **Network Layer** is essential for **inter-network communication**, handling:

- **Routing**: Selecting paths across multiple networks.  
- **Addressing**: Logical identification of devices using IP.  
- **Packet delivery**: Ensuring data reaches the correct destination.  

It is also a frequent target for attacks such as:

- **IP spoofing**
- **MITM**
- **Routing manipulation**
- **ICMP/Smurf flooding**

Effective protection requires:

- **Firewall and ACL implementation**  
- **Secure routing protocols with authentication**  
- **Network monitoring and IDS/IPS**  
- **VPNs and encryption for sensitive traffic**  

The Network Layer forms the **backbone of the Internet**, and securing it is vital for safe, reliable communication across global networks.

