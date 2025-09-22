# OSI vs TCP/IP Models – Complete Reference

This document provides a comprehensive overview of the **OSI 7-layer model** and the **TCP/IP 4-layer model**, including functionalities, devices, protocols, common attacks, and mitigation strategies.

---

## 1. Physical Layer (OSI Layer 1)

**Functionality:**  
- Transmits raw **bits** over a physical medium (cables, radio waves).  
- Handles **modulation, encoding, and signal transmission**.  
- Defines **physical topology and connectors**.  

**Devices:**  
- Hubs, Repeaters, NICs, Cables, Modems  

**Protocols:**  
- Ethernet (physical aspects), DSL, ISDN, RS-232  

**Attacks:**  
- Wiretapping, signal jamming, physical sabotage  

**Mitigation:**  
- Physical security, shielding, monitoring, cable management  

---

## 2. Data Link Layer (OSI Layer 2)

**Functionality:**  
- Provides **error detection/correction** using frames.  
- Controls **access to shared medium** (MAC addresses).  
- Handles **flow control** between directly connected nodes.  

**Sublayers:**  
1. **MAC Layer** – Physical addressing, media access control  
2. **LLC Layer** – Multiplexing and error control  

**Devices:**  
- Switches, Bridges, NICs  

**Protocols:**  
- Ethernet (802.3), Wi-Fi (802.11), PPP, ARP  

**Attacks:**  
- MAC spoofing, ARP poisoning, VLAN hopping  

**Mitigation:**  
- Port security, dynamic ARP inspection, VLAN segmentation  

---

## 3. Network Layer (OSI Layer 3 / TCP/IP Internet Layer)

**Functionality:**  
- Logical addressing (IP addresses), routing, packet forwarding.  
- Fragmentation/reassembly, traffic control, error handling.  

**Devices:**  
- Routers, Layer 3 switches, Gateways, Firewalls  

**Protocols:**  
- IPv4, IPv6, ICMP, IGMP, RIP, OSPF, BGP  

**Attacks:**  
- IP spoofing, ICMP flood, routing attacks, MITM  

**Mitigation:**  
- Packet filtering, ingress/egress filtering, VPN, secure routing, IDS/IPS  

---

## 4. Transport Layer (OSI Layer 4 / TCP/IP Transport Layer)

**Functionality:**  
- End-to-end communication, segmentation, error recovery, flow control.  
- Provides **connection-oriented (TCP)** and **connectionless (UDP)** services.  

**Devices:**  
- Firewalls, Load balancers, Gateways  

**Protocols:**  
- TCP, UDP, SCTP, DCCP  

**Attacks:**  
- TCP SYN flood, UDP flood, session hijacking, port scanning  

**Mitigation:**  
- SYN cookies, firewalls, rate limiting, TLS/SSL, IDS/IPS  

**TCP vs UDP Key Differences:**

| Feature                  | TCP                     | UDP                     |
|---------------------------|------------------------|------------------------|
| Connection                | Connection-oriented     | Connectionless         |
| Reliability               | Reliable (ACKs)         | Unreliable             |
| Ordering                  | Maintains sequence      | No ordering            |
| Error Handling            | Detection & Recovery    | Detection only         |
| Flow/Congestion Control   | Yes                     | No                     |
| Speed                     | Slower                  | Faster                 |
| Use Case                  | File transfer, email    | Streaming, gaming, VoIP|

---

## 5. Session Layer (OSI Layer 5)

**Functionality:**  
- Manages **sessions** between applications: setup, maintenance, termination.  
- Dialog control, synchronization, session recovery.  

**Devices:**  
- Gateways, Session Border Controllers (VoIP), Application servers  

**Protocols:**  
- NetBIOS, RPC, PPTP, SIP, SMB  

**Attacks:**  
- Session hijacking, replay attacks, session fixation, credential theft  

**Mitigation:**  
- Encryption (TLS/SSL), strong authentication, session timeouts, randomized session IDs  

---

## 6. Presentation Layer (OSI Layer 6)

**Functionality:**  
- Data **translation, formatting, encryption, compression**.  
- Ensures interoperability between different systems.  

**Devices:**  
- Application gateways, encryption devices, media codecs  

**Protocols:**  
- SSL/TLS, MIME, XDR, ASN.1, JPEG, MPEG, JSON, XML  

**Attacks:**  
- SSL stripping, MITM, serialization attacks, weak encryption, compression bombs  

**Mitigation:**  
- Strong encryption (TLS 1.3, AES-256), validate serialization, certificate verification, secure compression  

---

## 7. Application Layer (OSI Layer 7 / TCP/IP Application Layer)

**Functionality:**  
- Provides **network services directly to applications**.  
- Handles messaging, resource sharing, authentication, data formatting.  
- Integrates OSI Session, Presentation, and Application layers.  

**Devices:**  
- Application servers, proxies, gateways, client devices  

**Protocols:**  
- HTTP/HTTPS, FTP/SFTP, SMTP/IMAP/POP3, DNS, DHCP, SSH, Telnet, SNMP  

**Attacks:**  
- SQL injection, XSS, CSRF, HTTP floods, DNS spoofing, phishing, RCE  

**Mitigation:**  
- Input validation, secure protocols, MFA, WAFs, rate limiting, patch management, DNSSEC, secure email gateways  

---

## ✅ OSI vs TCP/IP Layer Mapping

| **OSI Layer**        | **TCP/IP Layer**      | **Example Protocols**          |
|-----------------------|-----------------------|--------------------------------|
| Application           | Application           | HTTP, FTP, SMTP, DNS           |
| Presentation          | Application           | SSL/TLS, JPEG, MPEG            |
| Session               | Application           | RPC, NetBIOS, SMB              |
| Transport             | Transport             | TCP, UDP                       |
| Network               | Internet              | IPv4, IPv6, ICMP, IGMP         |
| Data Link + Physical  | Network Access        | Ethernet, Wi-Fi, ARP, PPP      |

---

## ✅ Summary
- **OSI model** is a theoretical 7-layer model, useful for understanding networking concepts.  
- **TCP/IP model** is the practical 4-layer model used in the Internet today.  
- Each layer has **distinct functionalities, protocols, devices**, and **security considerations**.  
- Understanding both models is essential for **network design, troubleshooting, and cybersecurity**.
