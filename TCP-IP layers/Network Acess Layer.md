# 🌐 TCP/IP Model – Network Access Layer (Link Layer)

## 1. Functionality
- Defines how data is **physically transmitted** over the network medium (cables, radio waves).
- Encapsulates data into **frames** for transmission.
- Responsible for **MAC addressing**, **error detection** (via CRC), and **link establishment**.
- Ensures devices can communicate within the same local network.

---

## 2. Sublayers
The TCP/IP model merges Data Link + Physical layers into this one.
- **Data Link Functions**: Framing, error detection, MAC addressing.
- **Physical Functions**: Transmission of raw bits as electrical/optical/radio signals.

---

## 3. Devices
- **Switches**
- **Bridges**
- **Network Interface Cards (NICs)**
- **Access Points (APs)**
- **Hubs** (legacy)

---

## 4. Protocols
- **Ethernet (IEEE 802.3)**
- **Wi-Fi (IEEE 802.11)**
- **PPP (Point-to-Point Protocol)**
- **ARP (Address Resolution Protocol)**
- **Frame Relay**

---

## 5. Attacks
- **ARP Spoofing / ARP Poisoning** – attacker sends fake ARP replies to redirect traffic.
- **MAC Flooding** – overwhelms a switch’s MAC table, forcing it to act like a hub.
- **VLAN Hopping** – attacker gains access to restricted VLANs.
- **Physical Layer Attacks** – cable tapping, signal jamming, DoS on Wi-Fi.

---

## 6. Mitigation
- Enable **Dynamic ARP Inspection (DAI)** on switches.
- Use **Port Security** (limit MAC addresses per port).
- Implement **802.1X authentication** for access control.
- Physically secure cables and devices.
- Segment networks using **VLANs** and apply ACLs.
