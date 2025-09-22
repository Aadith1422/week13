# Physical Layer of the OSI Model

The **Physical Layer (Layer 1)** is the **lowest layer** in the OSI reference model. It is responsible for the **transmission and reception of raw bit streams** over a physical medium. Unlike higher layers, it does not deal with meaning or structure of data—only the **electrical, mechanical, and physical aspects** of communication.

---

## Functionalities of the Physical Layer
- **Bit Transmission** – Converts data (0s and 1s) into electrical signals, light pulses, or radio waves.  
- **Physical Topology** – Defines how devices are physically connected (bus, star, ring, mesh).  
- **Data Encoding and Signaling** – Specifies how bits are represented (e.g., NRZ, Manchester encoding).  
- **Synchronization** – Ensures sender and receiver interpret signals correctly.  
- **Transmission Modes** – Supports simplex, half-duplex, or full-duplex communication.  
- **Media Specification** – Defines cables (copper, fiber optic) or wireless frequencies.  
- **Data Rate Control** – Decides the transmission rate (bps).  
- **Physical Characteristics** – Voltages, pin layouts, modulation schemes.

---

## Sublayers of the Physical Layer
Although the OSI model itself does not subdivide the physical layer, IEEE standards split it into:

1. **Physical Medium Dependent (PMD) Sublayer**  
   - Handles actual signal transmission.  
   - Defines modulation, frequency, wavelengths, etc.  

2. **Physical Layer Convergence Protocol (PLCP) Sublayer**  
   - Provides an interface between MAC layer and PMD.  
   - Adds preamble, headers, and assists synchronization.  

---

## Devices Operating at the Physical Layer
- **Cables** (UTP, coaxial, fiber optic)  
- **Hubs**  
- **Repeaters**  
- **Modems**  
- **Network Interface Cards (NICs)** – partially operate here  
- **Media Converters**

---

## Protocols and Standards at the Physical Layer
The Physical Layer uses **standards** rather than traditional protocols:

- **Ethernet (IEEE 802.3)**  
- **Wi-Fi (IEEE 802.11)**  
- **Bluetooth (IEEE 802.15.1)**  
- **DSL, ISDN**  
- **USB**  
- **SONET/SDH**

---

## Attacks at the Physical Layer
- **Wiretapping / Eavesdropping** – tapping into cables.  
- **Jamming (DoS)** – interfering with wireless signals.  
- **Signal Interference / Noise Injection** – corrupting transmissions.  
- **Cable Cutting / Physical Damage** – sabotage of the medium.  
- **TEMPEST Attacks** – exploiting electromagnetic emissions.  
- **Hardware Theft/Manipulation** – tampering with devices.  

---

## Mitigation Techniques
- **Physical Security Controls** – locked rooms, restricted access, CCTV.  
- **Shielded Cables / Fiber Optics** – reduce interference/eavesdropping.  
- **Spread Spectrum Techniques** – resist jamming in wireless networks.  
- **Redundant Links & Media** – ensure availability during failures.  
- **Environmental Protections** – fire/flood/tamper safeguards.  
- **Faraday Cages / TEMPEST Shielding** – block electromagnetic leakage.  
- **Monitoring & Intrusion Detection** – detect unusual activity.  

---

## ✅ Summary
The Physical Layer ensures reliable **bit transmission** across physical media. While often overlooked, it is a critical vulnerability point since **physical access equals network access**. Securing it requires both **technical safeguards** (shielded cables, redundancy) and **physical protections** (restricted access, surveillance).
