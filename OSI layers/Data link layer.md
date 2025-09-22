# Data Link Layer of the OSI Model

The **Data Link Layer (Layer 2)** is the second layer of the OSI model.  
It is responsible for **node-to-node delivery** across a single physical link and ensures that data is **organized into frames, error-checked, and reliably sent** between devices directly connected on the same network segment.  

While the **Physical Layer (Layer 1)** deals with raw signals, the **Data Link Layer adds structure and reliability** to those signals by converting them into frames and handling addressing.

---

## Functionalities of the Data Link Layer

1. **Framing**  
   - Takes packets from the Network Layer and encapsulates them into **frames**.  
   - Each frame has a **header (with MAC addresses, control info)** and a **trailer (error-checking info like CRC)**.  

2. **MAC Addressing**  
   - Uses **Media Access Control (MAC) addresses** (unique identifiers burned into NICs).  
   - Ensures data is delivered to the correct device within the local network.  

3. **Error Detection & Correction**  
   - Detects errors using **CRC (Cyclic Redundancy Check), checksums, or parity bits**.  
   - Some protocols (like HDLC) also perform error correction by retransmission.  

4. **Flow Control**  
   - Prevents a fast sender from overwhelming a slower receiver.  
   - Uses methods like **stop-and-wait** or **sliding window protocols**.  

5. **Access Control (Media Control)**  
   - Decides which device can use the medium when multiple devices are connected.  
   - Examples:  
     - **Ethernet → CSMA/CD (Carrier Sense Multiple Access with Collision Detection)**  
     - **Wi-Fi → CSMA/CA (Collision Avoidance)**  

6. **Reliable Delivery (in some protocols)**  
   - Provides acknowledgment mechanisms (e.g., PPP, HDLC) to confirm frame delivery.  

---

## Sublayers of the Data Link Layer

The IEEE 802 standards divide the Data Link Layer into **two sublayers**:

### 1. Logical Link Control (LLC) Sublayer
- Interfaces with the **Network Layer** (above).  
- Provides error detection and flow control.  
- Allows multiple network protocols (like IPv4, IPv6, ARP) to coexist on the same physical medium.  
- Example: In Ethernet frames, LLC identifies whether the payload is IPv4, IPv6, or ARP.  

### 2. Media Access Control (MAC) Sublayer
- Interfaces with the **Physical Layer** (below).  
- Responsible for **framing, addressing, and media access control**.  
- Defines how devices share access to the transmission medium.  
- Ensures each frame has correct **source and destination MAC addresses**.  

---

## Devices Operating at the Data Link Layer

- **Switches**  
  - Forward frames using MAC addresses.  
  - Prevent collisions by creating separate collision domains.  

- **Bridges**  
  - Connect two LAN segments and filter traffic at Layer 2.  

- **Network Interface Cards (NICs)**  
  - Implement MAC addresses and provide hardware interface for communication.  

- **Access Points (Wireless LANs)**  
  - Operate at Layer 2 to manage wireless frame transmission.  

---

## Protocols at the Data Link Layer

- **Ethernet (IEEE 802.3)** – Wired LAN standard.  
- **Wi-Fi (IEEE 802.11)** – Wireless LAN standard.  
- **PPP (Point-to-Point Protocol)** – Used in serial connections (DSL, VPN tunnels).  
- **HDLC (High-Level Data Link Control)** – Used in point-to-point WAN links.  
- **Frame Relay** – Legacy WAN protocol.  
- **ARP (Address Resolution Protocol)** – Resolves IP (Layer 3) to MAC (Layer 2).  
- **STP (Spanning Tree Protocol)** – Prevents loops in switch-based networks.  
- **LLDP (Link Layer Discovery Protocol)** – Device discovery in LANs.  

---

## Attacks at the Data Link Layer

1. **MAC Spoofing**  
   - Attacker changes their MAC address to impersonate another device.  
   - Can bypass filters or impersonate a trusted device.  

2. **ARP Spoofing / ARP Poisoning**  
   - Attacker sends forged ARP replies to associate their MAC with another host’s IP.  
   - Enables **Man-in-the-Middle (MITM)** attacks.  

3. **MAC Flooding (Switch Attack)**  
   - Floods a switch with fake MAC addresses.  
   - Forces switch to act like a hub, broadcasting traffic everywhere → allows sniffing.  

4. **VLAN Hopping**  
   - Exploiting switch misconfigurations to access traffic from other VLANs.  

5. **Evil Twin Attack (Wireless)**  
   - Attacker sets up a fake Wi-Fi access point with the same SSID as a real one.  
   - Users connect, exposing their traffic to the attacker.  

6. **Man-in-the-Middle at Layer 2**  
   - Using ARP poisoning, an attacker intercepts traffic between two legitimate devices.  

---

## Mitigation Techniques

1. **Port Security on Switches**  
   - Limit number of MAC addresses per port.  
   - Disable a port if a new/unexpected MAC is detected.  

2. **Dynamic ARP Inspection (DAI)**  
   - Validates ARP packets to prevent ARP spoofing.  

3. **DHCP Snooping**  
   - Prevents rogue DHCP servers from issuing fake IP configurations.  

4. **Proper VLAN Configuration**  
   - Disable unused ports and assign them to a "blackhole VLAN".  
   - Use **VLAN tagging** and proper trunking rules to prevent VLAN hopping.  

5. **Strong Wi-Fi Security**  
   - Use WPA3 (or at least WPA2-Enterprise) to prevent wireless spoofing attacks.  

6. **MAC Address Filtering**  
   - Restrict which devices can connect (though spoofable, still adds a hurdle).  

7. **Intrusion Detection/Prevention Systems (IDS/IPS)**  
   - Detect anomalies in ARP, MAC tables, or VLAN traffic.  

8. **Regular Network Monitoring**  
   - Monitor switch logs and use network analyzers to detect suspicious activity.  

---

## Real-World Example

- In a corporate LAN:  
  - Switches forward Ethernet frames using MAC addresses.  
  - ARP is used to resolve the IP of the default gateway to its MAC.  
  - Attackers could exploit ARP poisoning to intercept employee traffic (MITM).  
  - Mitigation: Enable **Dynamic ARP Inspection** and use **secure VLANs**.  

---

## ✅ Summary

The **Data Link Layer** ensures reliable and organized communication between directly connected devices.  
It provides **framing, MAC addressing, error detection, and media access control**.  

However, being close to the hardware, it is a frequent target for attacks like:  
- **MAC Spoofing**  
- **ARP Poisoning**  
- **MAC Flooding**  
- **VLAN Hopping**  

Securing this layer requires:  
- **Switch security (Port Security, ARP Inspection, DHCP Snooping)**  
- **Proper VLAN configuration**  
- **Strong wireless encryption**  
- **Continuous monitoring and IDS/IPS deployment**  

This makes Layer 2 a **critical defense line** in modern network security.

