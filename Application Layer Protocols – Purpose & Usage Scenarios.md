# 📌 Application Layer Protocols – Purpose & Usage Scenarios

The **Application Layer** of the OSI and TCP/IP models provides services directly to the end-user. It defines how applications interact with the network and ensures that data is properly formatted, transmitted, and interpreted between communicating devices.

Below are the most commonly used **Application Layer protocols**, their **purpose**, and **real-world usage scenarios**:

---

## 1. HTTP (HyperText Transfer Protocol)

* **Purpose:**

  * Enables transfer of hypertext documents (HTML, CSS, JavaScript) between web browsers and servers.
  * Operates on **TCP port 80**.

* **Usage Scenarios:**

  * Accessing websites via `http://` URLs.
  * Transferring text, images, and multimedia on the web.
  * APIs and web applications relying on RESTful communication.

* **Security Note:**

  * Data is sent in **plaintext**; vulnerable to MITM attacks.

---

## 2. HTTPS (HyperText Transfer Protocol Secure)

* **Purpose:**

  * Secure version of HTTP using **SSL/TLS encryption**.
  * Provides confidentiality, integrity, and authentication.
  * Operates on **TCP port 443**.

* **Usage Scenarios:**

  * Secure web browsing (`https://` URLs).
  * Online banking, e-commerce, and confidential data exchange.
  * Protecting credentials in login forms.
  * Securing APIs, cloud services, and web apps.

* **Security Note:**

  * Prevents eavesdropping, tampering, and spoofing.

---

## 3. DNS (Domain Name System)

* **Purpose:**

  * Translates **domain names** into **IP addresses**.
  * Uses **UDP port 53** (TCP for zone transfers or large queries).

* **Usage Scenarios:**

  * Resolving website addresses before initiating connections.
  * Email delivery (MX record resolutions).
  * Load balancing using multiple IP addresses.
  * Internal corporate network name resolution.

* **Security Note:**

  * Vulnerable to **DNS spoofing/poisoning**.
  * Mitigation: **DNSSEC**.

---

## 4. FTP (File Transfer Protocol)

* **Purpose:**

  * Transfers files between client and server.
  * Supports authentication (username and password).
  * Operates on **TCP port 21** (control) and dynamic data ports.

* **Usage Scenarios:**

  * Uploading/downloading files to/from web servers.
  * Remote file management by administrators.
  * Distributing datasets, patches, or software updates.

* **Security Note:**

  * **FTP transmits credentials in plaintext**.
  * Secure alternatives: **FTPS**, **SFTP**.

---

## 📊 Summary Table

| Protocol  | Port         | Purpose                               | Usage Scenarios                               | Security Implications                       |
| --------- | ------------ | ------------------------------------- | --------------------------------------------- | ------------------------------------------- |
| **HTTP**  | 80           | Transfer hypertext/web pages          | Browsing websites, APIs                       | Insecure, vulnerable to MITM                |
| **HTTPS** | 443          | Secure web communication              | Online banking, e-commerce, secure browsing   | Encrypted, prevents MITM                    |
| **DNS**   | 53 (UDP/TCP) | Resolves domain names to IP addresses | Website access, email routing, load balancing | Vulnerable to spoofing; mitigated by DNSSEC |
| **FTP**   | 21           | File transfer                         | Web hosting, file sharing, software updates   | Insecure (plaintext); use SFTP/FTPS         |

---

This document provides **purpose, usage scenarios, and security considerations** for key Application Layer protocols.
