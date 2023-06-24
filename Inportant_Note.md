# Threat Intelligence

# Nmap

```bash
nmap –help
PORT SPECIFICATION AND SCAN ORDER:
-p : Only scan specified ports
Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
–exclude-ports : Exclude the specified ports from scanning
-F: Fast mode – Scan fewer ports than the default scan
-r: Scan ports consecutively – don’t randomize
–top-ports : Scan most common ports
–port-ratio : Scan ports more common 
```

# IP Address Decoy
IP address decoy technique refers to generating or manually specifying the IP addresses of decoys in order to evade an IDS or firewall.
`Nmap -D RND:10 <target IP address>`

# PKI

- PKI are use verify and authenticate the identity of individuals within the enterprise

# Common Port

- 113 port is used for Identification / Authorization service, TCP and UDP
- 69 port is Trivial File Transfer Protocol (TFTP), UDP
- 161 port Simple Network Management Protocol (SNMP), TCP and UDP
-  123 port NTP
-  ftp (port 21), option A. telnet (port 23) is not used for file transfer and ssh (port 22) is encrypted.

# Port 161 
- Port 161 Details. Simple network management protocol (SNMP). Used by various devices and applications (including firewalls and routers) to communicate logging and management information with remote monitoring applications.
- SNMP run on the UDP 161, and Secure Version is SNMPv3.

# Port 389
- TCP/UDP 389: Lightweight Directory Access Protocol (LDAP), LDAPS (LDAP over SSL) 636. (P.414/398)

# TCP/UDP 445: SMB over TCP (Direct Host)
Windows supports file- and printer-sharing traffic using the SMB protocol directly hosted on TCP. (P.413/397)


# Conducting Location Search on Social Media Sites
Such as Twitter, Instagram, and Facebook helps attackers to detect the geolocation of the target. This information further helps attackers to perform various social engineering and non-technical attacks.
Many online tools such as `Followerwonk`, `Hootsuite`, and `Sysomos` are available to search for both geotagged and non-geotagged information on social media sites. (P.183/167)
- HootSuite Enterprise provides geo-location and targeting functionality that give you insight into web traffic while driving customers to your door. Use location and language targeting to engage with your specific audience

# Vuln Scan

- Vulnerability Assessment Tools：
Qualys / Nessus / OpenVAS / Nikto / Nexpose
- Nikto is an Open Source (GPL) web server scanner that performs comprehensive tests against web servers for multiple items, including over 6 700 potentially dangerous files or programs, checks for outdated versions of over 1250 servers, and checks for version specific problems on over 270 servers. 

# Type of Scanner
1. `Network-Based Scanner`: Network-based scanners are those that interact only with the real machine where they reside and give the report to the same machine after scanning.

2. `Agent-Based Scanner`: Agent-based scanners reside on a single machine but can scan several machines on the same network. Agent-based scanners make use of software scanners on each and every device; the results of the scans are reported back to the central server. Such scanners are well equipped to find and report out on a range of vulnerabilities

3. `Proxy Scanner`: Proxy scanners are the network-based scanners that can scan networks from any machine on the network.

4. `Cluster scanner`: Cluster scanners are similar to proxy scanners, but they can simultaneously perform two or more scans on different machines in the network.

# Web Application Threats
- OWASP Top 10 Application Security Risks
Security Misconfiguration - Parameter/Form Tampering
- A web parameter tampering attack involves the manipulation of parameters exchanged between the client and the server to modify application data such as user credentials and permissions.
- This information is actually stored in cookies, hidden form fields, or URL query strings. (P.1770/1754)

# host command

- `host -t a hackeddomain.com`
With option "-t" you can specify the type of the DNS request.

# Security and Privacy Control

- NIST-800-53
The National Institute of Standards and Technology (NIST), within the U.S. Department of Commerce, creates standards and guidelines pertaining to information security.
NIST 800-53 mandates specific security and privacy controls required for federal government and critical infrastructure.
https://cloud.google.com/security/compliance/nist800-53/

# Scanning and footprinting

- Passive OS fingerprinting involves sniffing network traffic at any given collection point and matching known patterns that pass to a table of pre-established OS identities. No traffic is sent with passive fingerprinting.
Nmap does not use a passive style of fingerprinting. Instead it performs its Operating System Fingerprinting Scan (OSFS) via active methodologies.
- By observing specific characteristics of the packets, such as the Time To Live (TTL) value or specific flags, an analyst can infer information about the operating system of the device sending those packets. This process is passive because it doesn't require direct interaction with the target system, as the information is collected by simply monitoring the network traffic.
- OS Discovery/Banner Grabbing
Passive Banner Grabbing
Sniffing the network traffic - Capturing and analyzing packets from the target
- `(traceroute) and ping commands can't OS fingerprinting`

# Virus and Malware

- A boot sector virus is a type of virus that infects `the boot sector of floppy disks or the primary boot record of hard disks` (some infect the boot sector of the hard disk instead of the primary boot record). The infected code runs when the system is booted from an infected disk, but once loaded it will infect other floppy disks when accessed in the infected computer. While **boot sector viruses infect at a BIOS level**, they use DOS commands to spread to other floppy disks. For this reason, they started to fade from the scene after the appearance of Windows 95 (which made little use of DOS instructions). Today, there are programs known as ‘bootkits’ that write their code to the primary boot record as a means of loading early in the boot process and then concealing the actions of malware running under Windows. However, they are not designed to infect removable media.

The only absolute criteria for a boot sector is that it must contain 0x55 and 0xAA as its last two bytes. If this signature is not present or is corrupted, the computer may display an error message and refuse to boot. Problems with the sector may be due to physical drive corruption or the presence of a boot sector virus.

```
According to EC-Council Module07 Page 919
A boot sector virus moves MBR to another location on the hard disk and copies itself to the original location of MBR. When the system boots, first, the code executes and the control passes to the original MBR.
```

# Mulitpartite virus

- A multipartite virus is a fast-moving virus that uses file infectors or boot infectors to attack the boot sector and executable files
simultaneously.
- A multipartite virus (also known as a multipart virus or hybrid virus) combines the approach of file infectors and boot record infectors and attempts to `simultaneously` attack both the boot sector and the executable or program files

# Polymorphic virus

- Polymorphic viruses rely on mutation engines to alter their decryption routines every time they infect a machine. This way, traditional security solutions may not easily catch them because they do not use a static, unchanging code. The use of complex mutation engines that generate billions of decryption routines make them even more difficult to detect.
- They are designed to change their appearance or signature files to avoid detection by traditional antivirus software, which scans for specific files and looks for specific patterns. A polymorphic virus will continue changing its file names and physical location — not only after each infection, but as often as every 10 minutes
- URSNIF, VIRLOCK, VOBFUS, and BAGLE or UPolyX are some of the most notorious polymorphic viruses in existence

# Steath virus
- a stealth virus is a computer virus that uses various mechanisms to avoid detection by antivirus software. Generally, stealth describes any approach to doing something while avoiding notice
- The question includes: "can change its own code". `Encryption does nothing with the virus code`. It just encrypts it, and after some trigger decrypts it and the virus runs. Change of the key does nothing to the source code of virus, just changes the "presentation" form in encrypted state. I will definitely go with Poly/MetaMorphic ones but with provided answers Stealth fits better.
- `Stealth virus`: change its code + cipher ( this is way is called STEALTH, to avoid being detected)
`Encription virus`: cipher ( only cipher to avoid being detected)
- `A stealth virus` usually enters the system via infected web links, malicious email attachments, third-party application downloads, etc. The virus tricks the system to get past an antivirus program using two primary methods:

1. Code modification. To avoid detection, the virus modifies the code and virus signature of every infected file.
2. Data encryption. The virus renders the affected file inaccessible or unreadable to the user by encrypting it and also by using a different encryption key for different files.

Therefore answer is Stealth virus

# Encryption virus
- Encryption virus is just another name for Ransomware, as it encrypts the victim's files and folders.

# Fileless Malware

- Fileless Malware
Fileless malware can easily evade various security controls, organizations need to focus on monitoring, detecting, and preventing malicious activities instead of using traditional approaches such as scanning for malware through file signatures.Also known as non-malware, infects legitimate software, applications, and other protocols existing in the system to perform various malicious activities.It resides in the system’s RAM. It injects malicious code into the running processes
- bypass the company's application whitelisting

# Botnet Trojans
- They trick regular computer users into downloading Trojan-infected files to their systems through phishing, SEO hacking, URL redirection, etc. Once the user downloads and executes this botnet Trojan in the system, it connects back to the attacker using IRC channels and waits for further instructions.They help an attacker to launch various attacks and perform nefarious activities such as DoS attacks, spamming, click fraud, and theft of application serial numbers, login IDs, and credit card numbers. (P.886/870),`"coordinated attack" is the clue`

# Credential enumerator 
- is a self-extracting RAR file containing two components: a `bypass component` and a `service component`. 
- The bypass component is used for the enumeration of network resources and either finds writable share drives using Server Message Block (SMB) or tries to brute force user accounts, including the administrator account. 
- Once an available system is found, Emotet writes the service component on the system, which writes Emotet onto the disk. `Emotet’s access to SMB` can result in the infection of entire domains (servers and clients).

# Scareware
- Scareware is a type of malware that tricks computer users into visiting malware-infested websites or downloading or buying potentially malicious software. Scareware is often seen in pop-ups that tell the target user that their machine has been infected with malware. Further, these pop-up ads always have a sense of urgency. (P.1237/1221)

## Security administrator John Smith has noticed abnormal amounts of traffic coming from local computers at night. Upon reviewing, he finds that user data have been exfiltrated by an attacker. AV tools are unable to find any malicious software, and the IDS/IPS has not reported on any non-whitelisted programs.
What type of malware did the attacker use to bypass the company's application whitelisting?
A. File-less malware (Correct Answer)
B. Zero-day malware
C. Phishing malware
D. Logic bomb malware

# Sniffing

- Ethereal has a very good `graphical user interface`, can provide information on packet
- tcpdump is a common packet analyzer that runs under the `command line`

# DHCP snooping

- DHCP snooping is a security feature that acts like a firewall between untrusted hosts and trusted DHCP servers. The DHCP snooping feature performs the following activities: 
>- Validates DHCP messages received from untrusted sources and filters out invalid messages. •
##  Overview of Dynamic ARP Inspection
- Dynamic ARP Inspection (DAI) is a security feature that validates Address Resolution Protocol (ARP) packets in a network. DAI allows a network administrator to intercept, log, and discard ARP packets with invalid MAC address to IP address bindings. This capability protects the network from certain “man-in-the-middle” attacks.
- Defend Against ARP Poisoning
Implement Dynamic ARP Inspection(DAI) Using DHCP Snooping Binding Table.
- To validate the ARP packet, the DAI performs IP-address-to-MAC-address binding inspection stored in the DHCP snooping database before forwarding the packet to its destination. If any invalid IP address binds a MAC address, the DAI will discard the ARP packet. (P.1149/1133)

# Bob, a network administrator at BigUniversity, realized that some students are connecting their notebooks in the wired network to have Internet access. In the university campus, there are many Ethernet ports available for professors and authorized visitors but not for students. He identified this when the IDS alerted for malware activities in the network.
What should Bob do to avoid this problem?
A. Disable unused ports in the switches
B. Separate students in a different VLAN
C. Use the 802.1x protocol
D. Ask students to use the wireless network

# Answer is C `use 802.1x` prtocol

- How does 802.1X work?
802.1X is a network authentication protocol that opens ports for network access when an organization `authenticates a user’s identity and authorizes them for access to the network`. The user’s identity is determined based on their credentials or certificate, which is confirmed by the RADIUS server. The RADIUS server is able to do this by communicating with the organization’s directory, typically over the LDAP or SAML protocol.

- A is not possible, because if you disable the ports they cannot be used by teachers or authorized visitors. Answer C is correct, as this protocol requires users to authenticate to validate whether they have permissions to use the network or not.

# Fuzzing

- Attackers use the fuzzing technique to repeatedly send random input to the target API to generate error messages that reveal critical information.
- To perform fuzzing, attackers use automated scripts that send a huge number of requests with a varying combination of input parameters to achieve the goal

# Protocol Analyzer (eg. Wireshark)
- A protocol analyzer is a tool (hardware or software) used to capture and analyze signals and data traffic over a communication channel.
Purpose is to monitor network usage and identify malicious network traffic generated by hacking software installed on the network.
- You can use a sniffer to create a pcap file but you need a protocol analyzer. An example of a protocol analyzer is WireShark which you can clearly use to analyze a pcap file.
- Sniffer in general can be used only to capture the traffic. Protocol analyser is need to read the capture, parse it properly and provide you easy way to read the content.
- The confusion is that the most well known tool - Wireshark can do both, but those are two different roles.

# Heartbleed

- The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption used to secure the Internet.
- This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content.
- The data obtained by a Heartbleed attack may include unencrypted exchanges between TLS parties likely to be confidential, including any form post data in users’ requests. 
-  Moreover, the confidential data exposed could include authentication secrets such as session cookies and passwords, which might allow attackers to impersonate a user of the service.An attack may also reveal private keys of compromised parties

# Risk accessment
#### Apparently there 4 Critical Components of an Effective Risk Assessment. They are:
-Technical Safeguards
-Organisational Safeguards
-Physical Safeguards
-Administrative Safeguards
Src: https://www.digirad.com/four-critical-components-effective-risk-assessment/
- The `HIPAA Security Rule` establishes national standards to protect individuals’ electronic personal health information that is created, received, used, or maintained by a covered entity. The Security Rule requires appropriate `administrative`, `physical`, and `technical` safeguards to ensure the confidentiality, integrity, and security of electronically protected health information. CEHv11 book page 97 (81)

# Email spoofing

- `Email spoofing` is the creation of email messages with a forged sender address to make it look like a valid employee of the company, for example.
- `Masquerading` is when you spoof the mail and modify the content to look like a legitimate mail.
The mail protection system can detect a spoofed sender, but not a masqueraded content. It should block the spoofed sender.

# Bob, a system administrator at TPNQM SA, concluded one day that a DMZ is not needed if he properly configures the firewall to allow access just to servers/ports, which can have direct internet access, and block the access to workstations. Bob also concluded that DMZ makes sense just when a stateful firewall is available, which is not the case of TPNQM SA.
In this context, what can you say?
A. Bob can be right since DMZ does not make sense when combined with stateless firewalls
B. Bob is partially right. He does not need to separate networks if he can create rules by destination IPs, one by one
C. Bob is totally wrong. DMZ is always relevant when the company has internet servers and workstations Most Voted
D. Bob is partially right. DMZ does not make sense when a stateless firewall is available

- CEH chapter9, Perimeter Defense Mechanisms
## Answer is `B`

# SMTP Server 
SMTP provides 3 built-in-commands:
1. VRFY - Validates users
2. EXPN - Shows the actual delivery addresses of aliases and mailing lists
3. RCPT TO - Defines the recipients of a message

- According to your source Verify (VRFY) and Expand (EXPN) do the same thing. Upon further research it seems that VRFY is used to verify an (email) address and EXPN is used to determine the membership of a mailing list

# Infoga

- Infoga is a free and open-source tool, which is used for finding if emails were leaked using haveibeenpwned.com API. Infoga is used for scanning email addresses using different websites and search engines for information gathering and finding information about leaked information on websites and web apps.
- mail tracking tools allow an attacker to collect information such as IP addresses, mail servers, and service providers involved in sending the email. Attackers can use this information to build a hacking strategy and to perform social engineering and other attacks. Examples of email tracking tools include eMailTrackerPro, Infoga, and Mailtrack.

# IOT

- Information Gathering using FCC ID Search
FCC ID Search helps in finding the details and granted certification of the devices.
- FCC ID contains two elements: 
1. Grantee ID (initial three or five characters) and 
2. Product ID (remaining characters).
- Attackers can gather basic information about a target device using FCC ID Search available on https://www.fcc.gov/oet/ea/fccid
Using this information, an attacker can find underlying vulnerabilities in the target device and launch further attacks.

- FCC ID Search can be used to look up detailed information on the device if an FCC identification number is printed on the board (or found otherwise). This search will return information on the manufacturer, model, and chipset

# What is the port to block first in case you are suspicious that an IoT device has been compromised?
## ANS = Port 48101

- How to Defend Against IoT Hacking
Mirai, look for suspicious traffic on port 48101. Infected devices often attempt to spread malware by using port 48101 to send results to the threat actor.Monitor traffic on port 48101 as infected devices attempt to spread malicious file
- IOT Uses port 48101 and that is the port to monitor for potential issues then closing that port will stop IOT from communication with the network
- The question is incorrect, it is not about knowledge of the IoT security concept, but about knowledge of one of the largest DDos attacks using Mirai in 2016:

- On September 20, 2016, Brian Krebs’ security blog (krebsonsecurity.com) was targeted by a massive DDoS attack, one of the largest on record, exceeding 620 gigabits per second (Gbps). An IoT botnet powered by Mirai malware created the DDoS attack. The Mirai malware continuously scans the Internet for vulnerable IoT devices, which are then infected and used in botnet attacks. The Mirai bot uses a short list of 62 common default usernames and passwords to scan for vulnerable devices. Because many IoT devices are unsecured or weakly secured, this short dictionary allows the bot to access hundreds of thousands of devices.

- And one of Preventive Steps was:
- Look for suspicious traffic on port 48101. Infected devices often attempt to spread malware by using port 48101 to send results to the threat actor.

# Docker 

- The Docker daemon (dockerd) listens for Docker API requests and manages Docker objects such as images, containers, networks, and volumes. A daemon can also communicate with other daemons to manage Docker services


# You are a penetration tester working to test the user awareness of the employees of the client XYZ. You harvested two employees' emails from some public sources and are creating a client-side backdoor to send it to the employees via email.
Which stage of the cyber kill chain are you at?
A. Reconnaissance
B. Weaponization Most Voted
C. Command and control
D. Exploitation

## Ans - D (Exploitation)
- I feel the correct answer is weaponization (B) and not Exploitation (D). Question clearly states that the tester is "creating" the backdoor. It hasn't been sent to the victim yet. So recon was done, weaponization is next, then deliver via email (which is not yet done) and then exploitation. Thoughts?

# CVSS Score

```
Maybe this is a bit clearer?
Rating CVSS Score
None 0.0
Low 0.1 - 3.9
Medium 4.0 - 6.9
High 7.0 - 8.9
Critical 9.0 - 10.0
```


# Samuel, a security administrator, is assessing the configuration of a web server. He noticed that the server permits SSLv2 connections, and the same private key certificate is used on a different server that allows SSLv2 connections. This vulnerability makes the web server vulnerable to attacks as the SSLv2 server can leak key information.
Which of the following attacks can be performed by exploiting the above vulnerability?
A. Padding oracle attack
B. DROWN attack
C. DUHK attack
D. Side-channel attack

## ANS = B (DROWN attack)

# DROWN Attack
- DROWN attack allows an attacker to decrypt intercepted TLS connections by making specially crafted connections to an SSLv2 server that uses the same private key.
- The DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) attack is a cross-protocol security bug that attacks servers supporting modern SSLv3/TLS protocol suites by using their support for the obsolete, insecure, SSL v2 protocol to leverage an attack on connections using up-to-date protocols that would otherwise be secure.[1][2] DROWN can affect all types of servers that offer services encrypted with SSLv3/TLS yet still support SSLv2, provided they share the same public key credentials between the two protocols.[3] Additionally, if the same public key certificate is used on a different server that supports SSLv2, the TLS server is also vulnerable due to the SSLv2 server leaking key information that can be used against the TLS server.
-  A DROWN attack is a cross-protocol weakness that can communicate and initiate an attack on servers that support recent SSLv3/TLS protocol suites. A DROWN attack makes the attacker decrypt the latest TLS connection between the victim client and server by launching malicious SSLv2 probes using the same private key

# DUHK attack??



# LDAP enumeration

- Attackers can enumerate information such as valid usernames, addresses, and departmental details from different LDAP servers. Ex: Active Directory Explorer(AD Explorer)、JXplorer (P.439/423)

# ohnson, an attacker, performed online research for the contact details of reputed cybersecurity firms. He found the contact number of sibertech.org and dialed the number, claiming himself to represent a technical support team from a vendor. He warned that a specific server is about to be compromised and requested sibertech.org to follow the provided instructions. Consequently, he prompted the victim to execute unusual commands and install malicious files, which were then used to collect and pass critical information to Johnson's machine.
What is the social engineering technique Steve employed in the above scenario?
A. Diversion theft
B. Quid pro quo Most Voted
C. Elicitation
D. Phishing

## Ans - C (Elicitation)

- In summary, quid pro quo involves an exchange of something valuable for information or access, while elicitation involves questioning techniques to obtain information from the victim without an exchange of something valuable.
- Elicitation is a structured method of communication used to extract predetermined information from people without making them aware that they are a collection target. here the keyword is Collect which is used in the question
- This doesn't seem a Quid pro quo, because nothing is offered for something else
- Answer is elicitation. The person is calling pretenting to be someone they are not and eliciting information.
It is not B. Quid Pro Quo. This is 'something for something.' The attacker is not offering anything. They are demanding help under the guise of being someone else
- "quid pro quo" is explained in the CEH books as follows "Attackers call numerous random numbers within a company, claiming to be from technical support They offer their service to end users in exchange for confidential data or login credentials"

# To create a botnet, the attacker can use several techniques to scan vulnerable machines. The attacker first collects information about a large number of vulnerable machines to create a list. Subsequently, they infect the machines. The list is divided by assigning half of the list to the newly compromised machines.
The scanning process runs simultaneously. This technique ensures the spreading and installation of malicious code in little time.
Which technique is discussed here?
A. Subnet scanning technique
B. Permutation scanning technique
C. Hit-list scanning technique. Most Voted
D. Topological scanning technique
## Ans - D (Topological Scanning)

- Random Scanning - The infected machine probes IP addresses randomly from the target network IP range and checks for vulnerabilities

- Hit-list Scanning - An attacker first collects a list of potentially vulnerable machines and then scans them to find vulnerable machines

- Topological Scanning - It uses information obtained from an infected machine to find new vulnerable machines

- Local Subnet Scanning - The infected machine looks for new vulnerable machines in its own local network

- Permutation Scanning - It uses a pseudorandom permutation list of IP addresses to find new vulnerable machines

# An organization is performing a vulnerability assessment for mitigating threats. James, a pen tester, scanned the organization by building an inventory of the protocols found on the organization's machines to detect which ports are attached to services such as an email server, a web server, or a database server. After identifying the services, he selected the vulnerabilities on each machine and started executing only the relevant tests.
What is the type of vulnerability assessment solution that James employed in the above scenario?
A. Service-based solutions
B. Product-based solutions
C. Tree-based assessment
D. Inference-based assessment Most Voted
## ANS - D (Inference-based assessment)

- In an inference-based assessment, scanning starts by building an inventory of the
protocols found on the machine. After finding a protocol, the scanning process starts to detect which ports are attached to services, such as an email server, web server, or database server. After finding services, it selects vulnerabilities on each machine and starts to execute only those relevant tests
## Product based solution vs Service based solution
- Product based solutions are deployed within the network. Usually dedicated for internal network.
- Service based solutions are third-party solutions which offers security and auditing. This can be host either inside or outside the network. This can be a security risk of being compromised.
## Tree-based Assessment vs Inference-based Assessment
- Tree-based Assessment is the approach in which auditor follows different strategies for each component of an environment
- Inference-based Assessment is the approach to assist depending on the inventory of protocols in an environment

# Host-based assessments 
- are a type of security check that involve conducting a `configuration-level check` to identify system configurations, user directories, file systems, registry settings, and other parameters to evaluate the possibility of compromise.
- Host-based scanners assess systems to identify vulnerabilities such as `native configuration tables, incorrect registry or file permissions, and software configuration errors`. (P.528/512)

# .bash_history                     
- The SMB command uses the password to perform the login, this is stored in the bash_history. However, a log (xsession-log) never saves the credentials in its records.

# Robots.txt
- Information Gathering from Robots.txt File A website owner creates a robots.txt file to list the files or directories a web crawler should index for providing search results. Poorly written robots.txt files can cause the complete indexing of website files and directories. If confidential files and directories are indexed, an attacker may easily obtain information such as passwords, email addresses, hidden links, and membership areas. If the owner of the target website writes the robots.txt file without allowing the indexing of restricted pages for providing search results, an attacker can still view the robots.txt file of the site to discover restricted files and then view them to gather information. An attacker types URL/robots.txt in the address bar of a browser to view the target website’s robots.txt file. An attacker can also download the robots.txt file of a target website using the Wget tool.
Certified Ethical Hacker(CEH) Version 11 pg 1650

# Cloud Deployment Model

1. Community Cloud
Shared infrastructure between several organizations from a specific community with common concerns (security, compliance, jurisdiction, etc.) (P.2817/2801)
2. Public Cloud: In the public cloud model, cloud resources are owned and operated by a third-party service provider. These resources are made available to the general public or a large user base over the internet. Users can access and utilize computing resources, storage, and applications on a pay-per-use basis. Examples of public cloud providers include Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).

2. Private Cloud: A private cloud is dedicated to a single organization or entity. It can be owned, managed, and operated by the organization itself or a third-party provider exclusively for that organization. Private clouds offer increased control, security, and customization options compared to public clouds. They can be located on-premises, within the organization's data center, or hosted off-site.

3. Hybrid Cloud: The hybrid cloud model combines elements of both public and private clouds. It allows organizations to integrate their on-premises infrastructure with public cloud services. This enables businesses to maintain control over sensitive data and critical workloads in a private cloud while taking advantage of the scalability and flexibility offered by the public cloud for less sensitive or variable workloads. Hybrid clouds provide a balance between security, control, and cost-effectiveness.


# Andrew is an Ethical Hacker who was assigned the task of discovering all the active devices `hidden by a restrictive firewall` in the IPv4 range in a given target network.
Which of the following host discovery techniques must he use to perform the given task?
A. UDP scan
B. ARP ping scan Most Voted
C. ACK flag probe scan
D. TCP Maimon scan

## Ans - C  (ACK flag probe scan)

- " hidden by a restrictive firewall " so is will not by ARP, but ACK flag.

# An organization has automated the operation of critical infrastructure from a remote location. For this purpose, all the industrial control systems are connected to the Internet. To empower the manufacturing process, ensure the reliability of industrial networks, and reduce downtime and service disruption, the organization decided to install an OT security tool that further protects against security incidents such as cyber espionage, zero-day attacks, and malware.
Which of the following tools must the organization employ to protect its critical infrastructure?
A. Robotium
B. BalenaCloud
C. Flowmon Most Voted
D. IntentFuzzer

## Ans - B (Balena Cloud)

A. Robotium -- Android
B. BalenaCloud -- Clouid provider
C. Flowmon -- rather that, OT thing
D. IntentFuzzer -- Android

# IDS Evasion 

## Obfuscating 
- Obfuscating is an IDS evasion technique used by attackers who encode the attack packet payload in such a way that the destination host can decode the packet but not the IDS. Encode attack patterns in unicode to bypass IDS filters, but be understood by an IIS web server. (P.1548/1532)

## DNS Tunneling
#### Bypassing Firewalls through the DNS Tunneling Method
- DNS operates using UDP, and it has a 255-byte limit on outbound queries. Moreover, it allows only alphanumeric characters and hyphens. Such small size constraints on external queries allow DNS to be used as an ideal choice to perform data exfiltration by various malicious entities. Since corrupt or malicious data can be secretly embedded into the DNS protocol packets, even DNSSEC cannot detect the abnormality in DNS tunneling. It is effectively used by malware to bypass the firewall to maintain communication between the victim machine and the C&C server. Tools such as NSTX (https://sourceforge.net), Heyoka (http://heyoka.sourceforge.netuse), and Iodine (https://code.kryo.se) use this technique of tunneling traffic across DNS port 53.
CEH v11 Module 12 Page 994
- Bypassing Firewalls through the DNS Tunneling Method
Tools：NSTX, Heyoka, and Iodine use this technique of tunneling traffic across DNS port 53. (P.1586/1570)

 # Packet Fragmentation
- SYN/FIN Scanning Using IP Fragments The TCP header is split into several packets so that the packet filters are not able to detect what the packets are intended to do. (P.354/338)#

## DNSSEC Zone walking
#### To distinguish fro zone walking:
- Domain Name System Security Extensions (DNSSEC) zone walking is a type of DNS enumeration technique in which an attacker attempts to obtain internal records if the DNS zone is not properly configured. The enumerated zone information can assist the attacker in building a host network map. Organizations use DNSSEC to add security features to the DNS data and provide protection against known threats to the DNS. This security feature uses digital signatures based on public-key cryptography to strengthen authentication in DNS. These digital signatures are stored in the DNS name servers along with common records such as MX, A, AAAA, and CNAME. While

# Case Variations
By default, in most database servers, SQL is case insensitive.Owing to the case-insensitive option of regular expression signatures in the filters, attackers can mix upper and lower case letters in an attack vector to bypass the detection mechanism.
```
the attacker can easily bypass the filter using the following query:UnIoN sEleCt UsEr_iD, PaSSwOrd fROm aDmiN wHeRe UseR_NamE=’AdMIn’-- (P.2151/2135)

```
# Type of Rootkits

##  Kernel-Level Rootkit
- Add malicious code or replaces the original OS kernel and device driver codes.They are difficult to detect and can intercept or subvert the operation of an OS. (P.752/736)
- Kernel rootkits are installed in RING ZERO, prior to AntiMalware software being installed in RING 3. RING 3 apps can't inspect RING 0 due to lack of the appropriate privilege's for RING 3.

# Jim, a professional hacker, targeted an organization that is operating critical industrial infrastructure. Jim used Nmap to scan open ports and running services on systems connected to the organization's OT network. He used an Nmap command to identify Ethernet/IP devices connected to the Internet and further gathered information such as the vendor name, product code and name, device name, and IP address.
Which of the following Nmap commands helped Jim retrieve the required information?
A. nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p < Port List > < Target IP >
B. nmap -Pn -sU -p 44818 --script enip-info < Target IP > Most Voted
C. nmap -Pn -sT -p 46824 < Target IP >
D. nmap -Pn -sT -p 102 --script s7-info < Target IP >
## Ans -B 

- Enumerating Ethernet/IP devices
Ethernet/IP is a very popular protocol used in industrial systems that uses Ethernet as the transport layer and CIP for providing services and profiles needed for the applications. Ethernet/IP devices by several vendors usually operate on UDP port 44818 and we can gather information such as vendor name, product name, serial number, device type, product code, internal IP address, and version.
- enip-info: This NSE script is used to send a EtherNet/IP packet to a remote device that has TCP 44818 open. The script will send a Request Identity Packet and once a response is received, it validates that it was a proper response to the command that was sent, and then will parse out the data. Information that is parsed includes Device Type, Vendor ID, Product name, Serial Number, Product code, Revision Number, status, state, as well as the Device IP.
so it scans that ports auto.


# Ciphers - Triple Data Encryption Standard (3DES)
- Essentially, it performs DES three times with three different keys. 3DES uses a “key bundle” that comprises three DES keys, K1, K2, and K3. Each key is a standard 56-bit DES key.


# Gerard, a disgruntled ex-employee of Sunglass IT Solutions, targets this organization to perform sophisticated attacks and bring down its reputation in the market.
To launch the attacks process, he performed DNS footprinting to gather information about DNS servers and to identify the hosts connected in the target network.
He used an automated tool that can retrieve information about DNS zone data including DNS domain names, computer names, IP addresses, DNS records, and network Whois records. He further exploited this information to launch other sophisticated attacks.
What is the tool employed by Gerard in the above scenario?
A. Towelroot
B. Knative
C. zANTI
D. Bluto (Correct Answer)

- DNS FootprintingExtracting DNS Information
DNS Footprinting - Extracting DNS Information
DNS lookup tools such as DNSdumpster.com, Bluto, and Domain Dossier to retrieve DNS records for a specified domain or hostname. These tools retrieve information such as domains and IP addresses, domain Whois records, DNS records, and network Whois records. (P.220/204)
- Bluto...
"Attackers also use DNS lookup tools such as DNSdumpster.com, Bluto, and Domain Dossier to retrieve DNS records for a specified domain or hostname. These tools retrieve information such as domains and IP addresses, domain Whois records, DNS records, and network Whois records." CEH Module 02 Page 138

# Steven connected his iPhone to a public computer that had been infected by Clark, an attacker. After establishing the connection with the public computer, Steven enabled iTunes Wi-Fi sync on the computer so that the device could continue communication with that computer even after being physically disconnected. Now,
Clark gains access to Steven's iPhone through the infected computer and is able to monitor and read all of Steven's activity on the iPhone, even after the device is out of the communication zone.
Which of the following attacks is performed by Clark in the above scenario?
A. Man-in-the-disk attack
B. iOS jailbreaking
C. iOS trustjacking (Correct Answer)
D. Exploiting SS7 vulnerability

- "iOS Trustjacking is a vulnerability that can be exploited by an attacker to read messages and emails and capture sensitive information such as passwords and banking credentials from a remote location without a victim’s knowledge. This vulnerability exploits the “iTunes Wi-Fi Sync” feature whereby a victim connects his/her phone to any trusted computer (could be of a friend or any trusted entity) that is already infected by the attacker."
CEH Module 17 Page 1521
- https://borwell.com/2018/09/06/ios-trustjacking/

# Five Tier Container Technology

- Tier-1: Developer machines - image creation, testing and accreditation

- Tier-2: Testing and accreditation systems - verification and validation of image contents, signing images and sending them to the registries.


- Tier-3: Registries - storing images and disseminating images to the orchestrators based on requests.


- Tier-4: Orchestrators - transforming images into containers and deploying containers to hosts.



- Tier-5: Hosts - operating and managing containers as instructed by the orchestrator.

# Abel, a cloud architect, uses container technology to deploy applications/software including all its dependencies, such as libraries and configuration files, binaries, and other resources that run independently from other processes in the cloud environment. For the containerization of applications, he follows the five-tier container technology architecture. Currently, Abel is verifying and validating image contents, signing images, and sending them to the registries.
Which of the following tiers of the container technology architecture is Abel currently working in?
A. Tier-1: Developer machines
B. Tier-2: Testing and accreditation systems Most Voted ?????
C. Tier-3: Registries ?????
D. Tier-4: Orchestrators

**Most answer B is correct but examtopic show C is correct and I think B is correct**

# Monitoring Website Traffic of Target Company
- Attackers can monitor a target company’s website traffic using tools such as Web-Stat, Alexa, and Monitis to collect valuable information.
- `Live visitors map`: Tools such as Web-Stat track the geographical location of the users visiting the company’s website. (P.206/190)

# Wireless Network Assessment
- Wireless network assessment determines the vulnerabilities in an organization’s wireless networks. In the past, wireless networks used weak and defective data encryption mechanisms. Now, wireless network standards have evolved, but many networks still use weak and outdated security mechanisms and are open to attack. Wireless network assessments try to attack wireless authentication mechanisms and gain unauthorized access. This type of assessment tests wireless networks and identifies rogue networks that may exist within an organization’s perimeter. These assessments audit client-specified sites with a wireless network. They sniff wireless network traffic and try to crack encryption keys. Auditors test other network access if they gain access to the wireless network.


# Joe works as an IT administrator in an organization and has recently set up a cloud computing service for the organization. To implement this service, he reached out to a telecom company for providing Internet connectivity and transport services between the organization and the cloud service provider.
In the NIST cloud deployment reference architecture, under which category does the telecom company fall in the above scenario?
A. Cloud consumer
B. Cloud broker
C. Cloud auditor
D. Cloud carrier (Correct Answer)

- NIST Cloud Deployment Reference Architecture
Cloud Carrier - An intermediary for providing connectivity and transport services between cloud consumers and providers. (P.2823/2807)

# Agent Smith Attacks

- Agent Smith attacks are carried out by luring victims into downloading and installing malicious
apps designed and published by attackers in the form of games, photo editors, or other attractive tools from third-party app stores such as 9Apps. Once the user has installed the app, the core malicious code inside the application infects or replaces the legitimate apps in the victim’s mobile device C&C commands. The deceptive application replaces legitimate apps such as WhatsApp, SHAREit, and MX Player with similar infected versions. The application sometimes also appears to be an authentic Google product such as Google Updater or Themes. The attacker then produces a massive volume of irrelevant and fraudulent advertisements on the victim’s device through the infected app for financial gain. Attackers exploit these apps to steal critical information such as personal information, credentials, and bank details, from the victim’s mobile device through C&C commands

# This form of encryption algorithm is a symmetric key block cipher that is characterized by a 128-bit block size, and its key size can be up to 256 bits. Which among the following is this encryption algorithm?
A. HMAC encryption algorithm
B. Twofish encryption algorithm (Correct Answer)
C. IDEA
D. Blowfish encryption algorithm

- Blowfish has bigger size then 256bit, idea has just 64bit. HMAC is for hashing not encytpting
- Twofish uses a block size of 128 bits and key sizes up to 256 bits. It is a Feistel cipher.encryption speed. 
- 256 synonymous to two fish, na my own way be that, blowfish is from 32 to 248 bit, it really blow

# Ethical hacker Jane Smith is attempting to perform an SQL injection attack. She wants to test the response time of a true or false response and wants to use a second command to determine whether the database will return true or false results for user IDs.
Which two SQL injection types would give her the results she is looking for?
A. Out of band and boolean-based
B. Union-based and error-based (True Answer)
C. Time-based and union-based
D. Time-based and boolean-based Most Voted


- Union based SQL injection allows an attacker to extract information from the database by extending the results returned by the first query. The Union operator can only be used if the original/new queries have an equivalent structure Error-based SQL injection is an In-band injection technique where the error output from the SQL database is employed to control the info inside the database. In In-band injection, the attacker uses an equivalent channel for both attacks and collect data from the database. 
- Not sure about D. Yes, it fits, could perfetcly be but...
"... wants to use a second command..." points directly to a UNION query. And yes, you can craft a UNION query to send a time- based request and a True/ false one too...


# Slowloris Attack
- Slowloris is a DDoS attack tool used to perform layer-7 DDoS attacks to take down web infrastructure. It is distinctly different from other tools in that it uses perfectly legitimate HTTP traffic to take down a target server. In Slowloris attacks, the attacker sends partial HTTP requests to the target web server or application. Upon receiving the partial requests, the target server opens multiple connections and waits for the requests to complete. However, these requests remain incomplete, causing the target server’s maximum concurrent connection pool to be filled up and additional connection attempts to be denied.
CEHv11 page 1322
- The following are examples for application layer attack techniques:
*Hypertext Transfer Protocol (HTTP) flood attack
*Slowloris attack
*UDP application layer flood attack

# ession fixation attack
Session Fixation is an attack that allows an attacker to hijack a sound user session. The attack explores a limitation within the means the net application manages the session ID, a lot of specifically the vulnerable web application. once authenticating a user, it doesn’t assign a new session ID, creating it possible to use an existent session ID. The attack consists of getting a valid session ID (e.g. by connecting to the application), inducing a user to authenticate himself with that session ID, then hijacking the user-validated session by the data of the used session ID. The attacker has got to give a legitimate internet application session ID and try to make the victim’s browser use it.


# Gilbert, a web developer, uses a centralized web API to reduce complexity and increase the integrity of updating and changing data. For this purpose, he uses a web service that uses HTTP methods such as PUT, POST, GET, and DELETE and can improve the overall performance, visibility, scalability, reliability, and portability of an application.
What is the type of web-service API mentioned in the above scenario?
A. RESTful API (correct answer)
B. JSON-RPC
C. SOAP API
D. REST API

- RESTful API: RESTful API is a RESTful service that is designed using REST principles and HTTP communication protocols. RESTful is a collection of resources that use HTTP methods such as PUT, POST, GET, and DELETE. RESTful API is also designed to make applications independent to improve the overall performance, visibility, scalability, reliability, and portability of an application. APIs with the following features can be referred to as to RESTful APIs: o Stateless: The client end stores the state of the session; the server is restricted to save data during the request processing
o Cacheable: The client should save responses (representations) in the cache. This feature can enhance API performance
pg. 1920 CEHv11 manual.
- Web Services APIs - RESTful API
also known as RESTful services, are designed using REST principles and HTTP communication protocols. RESTful is a collection of resources that use HTTP methods such as PUT, POST, GET, and DELETE.RESTful API is also designed to make applications independent to improve the overall performance, visibility, scalability, reliability, and portability of an application. (P.1920/1904)

# Blind Hijacking Attack

- acker may use techniques such as session prediction or IP spoofing. Session prediction involves `guessing the session ID` or other information used to identify the session, while IP spoofing involves forging the IP address of one of the machines in the session in order to gain access to the communication channel.
-  attacker guessing the next sequence. If the attacker was `not predicting` the next sequence it would `TCP/IP Hijacking`.
-  TCP/IP hijacking involves using spoofed packets to seize control of a connection between a victim and target machine. 

# Port Scanning

- ACK -> no response = filtered
- ACK -> RST/ACK = unfiltered

# If you send a TCP ACK segment to a known closed port on a firewall but it does not respond with an RST, what do you know about the firewall you are scanning?
A. It is a non-stateful firewall.
B. There is no firewall in place.
C. It is a stateful firewall. 
D. This event does not tell you anything about the firewall. (`Correct Answer`)
- I'm also going with D and this is why:
The question says that you are knocking on a known closed port on the Firewall. This is important.
If you know beforehand the port is closed on the firewall itself, you won't get any response regardless if it's a stateless or statefull firewall.
- What most people are saying about detecting stateful firewalls is with regards to an open port on the firewall... If the port is open on the firewall and you try to inject an ACK packet, a stateful firewall will understand that's an unsolicited packet and discard it, so you get no response from the server itself

# AndroidManifest.xml 
- which consists of essential information about the APK file.
- Note: The manifest file contains important information about the app that is used by development tools, the Android system, and app stores. It contains the app’s package name, version information, declarations of app components, requested permissions, and other important data. It is serialized into a binary XML format and bundled inside the app’s APK file.
- A. AndroidManifest.xml - Every app project must have an AndroidManifest.xml file (with precisely that name) at the root of the project source set. The manifest file describes essential information about your app to the Android build tools, the Android operating system, and Google Play.
- Among many other things, the manifest file is required to declare the following:

- The app's package name, which usually matches your code's namespace. The Android build tools use this to determine the location of code entities when building your project. When packaging the app, the build tools replace this value with the application ID from the Gradle build files, which is used as the unique app identifier on the system and on Google Play. Read more about the package name and app ID.
The components of the app, which include all activities, services, broadcast receivers, and content providers. Each component must define basic properties such as the name of its Kotlin or Java class. It can also declare capabilities such as which device configurations it can handle, and intent filters that describe how the component can be started. Read more about app components ...

# DNS Cache Poisoning
- DNS cache poisoning attack, but the first step would always be the same: the attacker must send queries to the DNS server to learn about the name resolution process and cache records. Then, the attacker can exploit the weaknesses found to poison the DNS cache and redirect traffic to malicious sites.
- DNS CACHE Poisoning refers to altering or adding forged DNS records in the DNS resolver cache so that a DNS query is redirected to a malicious site.
However, the question is asking the FIRST STEP for a hacker. The forged and altered DNS records are the end result.
The FIRST STEP is the attacker Queries for DNS info.
(P.1165/1181)
- I dont understand how people can not see the answers from their reference. Guys look at the diagram carefully 1st step you will see very clearly- " Query for DNS info" 1st step.
Subject is closed. Dont waste your time.

# Password Salting
Password salting is a technique where a random string of characters are added to the password before calculating their hashes.Advantage: Salting makes it more difficult to reverse the hashes and defeat pre-computed hash attacks.
#Note: Windows password hashes are not salted. (P.616/600)

# Whois Footprinting
which helps in gathering domain information such as information regarding the owner of an organization, its registrar, registration details, its name server, and contact information.
Regional Internet Registries (RIRs) maintain Whois databases, which contain the personal information of domain owners.
- Using this information, an attacker can create a map of the organization's network, mislead domain owners with social engineering, and then obtain internal details of the network. RIRs includ: ARIN (American Registry for Internet Numbers). (P.214/198)
- `https://search.arin.net/rdap/?query=199.43.0.43
`

# WPA3 - Enterprise
- It protects sensitive data using many cryptographic algorithms
It provides authenticated encryption using GCMP-256
It uses HMAC-SHA-384 to generate cryptographic keys It uses ECDSA-384 for exchanging keys

# Web Server Attacks - DNS Server Hijacking
- Attacker compromises the DNS server and changes the DNS settings so that all the requests coming towards the target web server are redirected to his/her own malicious server. (P.1623/1607)

# Web Server Attacks - Web Server Misconfiguration
Server misconfiguration refers to configuration weaknesses in web infrastructure that can be exploited to launch various attacks on web servers such as directory traversal, server intrusion, and data theft.
-  `php.ini file` - This configuration generates verbose error messages.
-
# Web Server Attacks - DHCP Starvation Attack

- This is a denial-of-service (DoS) attack on the DHCP servers where the attacker broadcasts forged DHCP requests and tries to lease all the DHCP addresses available in the DHCP scope
Therefore, the legitimate user is unable to obtain or renew an IP address requested via DHCP, and fails to get access to the network
- In a DHCP starvation attack, an attacker floods the DHCP server by sending numerous DHCP requests and uses all of the available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to a DoS attack. Because of this issue, valid users cannot obtain or renew their IP addresses; thus, they fail to access their network. An attacker broadcasts DHCP requests with spoofed MAC addresses with the help of tools such as Yersinia, Hyenae, and Gobbler.

# How to Identify Target System OS
- Attackers can identify the OS running on the target machine by looking at the Time To Live (TTL) and TCP window size in the IP header of the first packet in a TCP session.Sniff/capture the response generated from the target machine using packet-sniffing tools like Wireshark and observe the TTL and TCP window size fields.
#Time to Live (TTL) 128 is Windows / TTL 64 is Linux (P.341/325)

# Types of hardware encryption devices - Trusted platform module (TPM)
- TPM is a crypto-processor or a chip that is present in the motherboard. It can securely store the encryption keys and perform many cryptographic operations. TPM offers various features such as authenticating platform integrity, providing full disk encryption capabilities, performing password storage, and providing software license protection. (P.3058/3042)

# Management Information Base (MIB)
- DHCP.MIB: Monitors network traffic between DHCP servers and remote hosts
- HOSTMIB.MIB: Monitors and manages host resources
- LNMIB2.MIB: Contains object types for workstation and server services
- MIB_II.MIB: Manages TCP/IP-based Internet using a simple architecture and system
- WINS.MIB: For the Windows Internet Name Service (WINS)

# Bluetooth Hacking
- (A) `BlueSmacking` is a technique to performe a  `Denial of Service attack` into Bluetooth devices abuzing the L2PCAP layer.
- (B) `Bluejacking` is the sending of `unsolicited messages over Bluetooth` to Bluetooth-enabled devices
	- Bluejacking is the use of Bluetooth to send messages to users without the recipient's consent, similar to email spamming. Prior to any Bluetooth communication, the device initiating the connection must provide a name that is displayed on the recipient's screen. Sending anonymous messages over Bluetooth to Bluetooth-enabled devices, via the OBEX(Object Exchange) protocol. (P.2344/2328)
- (C) `Bluesnarfing` is an attack to `access information from wireless devices that transmit using the Bluetooth protocol`.
- (D) `Bluebugging` is a hacking technique that `allows individuals to access a device with a discoverable Bluetooth connection.`

# aLTEr attack
- aLTEr attacks are usually performed on LTE devices
- Attacker installs a virtual (fake) communication tower between two authentic endpoints intending to mislead the victim
- This virtual tower is used to interrupt the data transmission between the user and real tower attempting to hijack the active session.

# Incident Handling and Response

1. Preparation
2. Incident Recording and Assignment
3. Incident Triage
4. Notification
5. Containment
6. Evidence Gathering and Forensic Analysis

# Clark is a professional hacker. He created and configured multiple domains pointing to the same host to switch quickly between the domains and avoid detection.
Identify the behavior of the adversary in the above scenario.
A. Unspecified proxy activities (Correct Answer)
B. Use of command-line interface
C. Data staging
D. Use of DNS tunneling

- `Unspecified Proxy Activities` An adversary can create and configure multiple domains pointing to the same host, thus, allowing an adversary to switch quickly between the domains to avoid detection. Security professionals can find unspecified domains by checking the data feeds that are generated by those domains. Using this data feed, the security professionals can also find any malicious files downloaded and the unsolicited communication with the outside network based on the domains
- Adversary Behavioral Identification
Adversary behavioral identification involves the identification of the common methods or techniques followed by an adversary to launch attacks on or to penetrate an organization’s network.It gives the security professionals insight into upcoming threats and exploits.
3.Unspecified Proxy Activities - An adversary can create and configure multiple domains pointing to the same host, thus, allowing an adversary to switch quickly between the domains to avoid detection. (P.38/22)


# SE Techniques

# Pharming
- Pharming is a social engineering technique in which the attacker executes malicious programs on a victim’s computer or server, and when the victim enters any URL or domain name, it automatically redirects the victim’s traffic to an attacker-controlled website. This attack is also known as “Phishing without a Lure.” The attacker steals confidential information like credentials, banking details, and other information related to web-based services.

# Skimming 
- refers to stealing credit or debit card numbers by using special storage devices called skimmers or wedges when processing the card.

# Pretexting 
- Fraudsters may impersonate executives from financial institutions, telephone companies, and other businesses. They rely on “smooth-talking” and win the trust of an individual to reveal sensitive information.


# Dragonblood Vulnerability on wireless network
is a set of vulnerabilities in the `WPA3 security standard that allows attackers to recover keys, downgrade security mechanisms, and launch various information-theft attacks`
- Attackers can use various tools, such as `Dragonslayer`, `Dragonforce`, `Dragondrain`, and `Dragontime`, to exploit these vulnerabilities and launch attacks on WPA3-enabled networks.
- The design flaws we discovered can be divided in two categories. `The first category` consists of downgrade attacks against WPA3-capable devices, and `the second category` consists of weaknesses in the Dragonfly handshake of WPA3, which in the Wi-Fi standard is better known as the Simultaneous Authentication of Equals (SAE) handshake. 
- The discovered flaws can be abused to recover the password of the Wi-Fi network, launch resource consumption attacks, and force devices into using weaker security groups. All attacks are against home networks (i.e. WPA3-Personal), where one password is shared among all users.

# Advanced Persistent Threats (APTs)
- Advanced persistent threats (APTs) are defined as a type of network attack, where an attacker gains unauthorized access to a target network and remains `undetected for a long period` of time.Attacks is to obtain sensitive information rather than sabotaging the organization and its network. (P.865/849)
- he word “persistent” signifies the external command-and-control (C&C) system that continuously extracts the data and monitors the victim’s network. The word “threat” signifies human involvement in coordination. APT attacks are highly sophisticated attacks whereby an attacker uses well-crafted malicious code along with a combination of multiple zero-day exploits to gain access to the target network.

# DLE/IPID header scan
- Every IP packet on the Internet has a fragment identification number (IPID); an OS increases the IPID for each packet sent, thus, probing an IPID gives an attacker the number of packets sent after the last probe.
- IPID increased by 2 will indicate an open port , 1 will indicate a closed port.
- `Nmap -sI <Zombie IP address> <target IP address> (P.315/299`

# Jailbreak

- Untethered jailbreak, a type of iOS jailbreak that allows a device to boot up jailbroken every time it is rebooted. This does NOT require a “re-jailbreaking” process. The only way to get rid of a jailbreak using this process is to restore the device.
- he invalid options are (for reference):
Semi-tethered Jailbreaking: A semi-tethered jailbreak has the property that if the user turns the device off and back on, the device will completely start up and will no longer have a patched kernel, but it will still be usable for normal functions. To use jailbroken addons, the user need to start the device with the help of a jailbreaking tool

- Tethered Jailbreaking: With a tethered jailbreak, if the device starts back up on its own, it will no longer have a patched kernel, and it may get stuck in a partially started state; for it to completely start up with a patched kernel, it must be "re-jailbroken" with a computer (using the "boot tethered" feature of a jailbreaking tool) each time it is turned on

- Semi-untethered Jailbreaking A semi-untethered jailbreak is similar to a semi-tethered jailbreak. In this type of a jailbreak, when the device reboots, the kernel is not patched, but the kernel can still be patched without using a computer. This is done using an app installed on the device
- In a tethered jailbreak, the jailbreak software modifies the kernel of the iOS device to remove software restrictions and allow for the installation of third-party applications. However, this modification is not permanent and is lost when the device is rebooted.

- To maintain the jailbreak, the user must connect the device to a computer and run the jailbreak software again. The software patches the kernel during the boot process, allowing the device to become jailbroken once again.

- Tethered jailbreaking is generally considered less desirable than untethered jailbreaking, as it requires the user to connect the device to a computer each time it is rebooted. Untethered jailbreaking, on the other hand, does not require the user to connect the device to a computer to maintain the jailbreak.

- It's important to note that jailbreaking an iOS device can potentially expose the device to security risks and can void its warranty. Users should carefully consider the risks and benefits before deciding to jailbreak their iOS device.

# Webhooks 
- are user-defined HTTP callback or push APIs that are raised based on events
triggered, such as comment received on a post and pushing code to the registry. A webhook allows an application to update other applications with the latest information. Once invoked, it supplies data to the other applications, which means that users instantly receive real-time information. Webhooks are sometimes called “Reverse APIs” as they provide what is required for API specification, and the developer should create an API to use a webhook.
- What are Webhooks? Webhooks are user-defined HTTP callback or push APIs that are raised based on events triggered, such as comment received on a post and pushing code to the registry. A webhook allows an application to update other applications with the latest information. Once invoked, it supplies data to the other applications, which means that users instantly receive real-time information. Webhooks are sometimes called “Reverse APIs” as they provide what is required for API specification, and the developer should create an API to use a webhook. A webhook is an API concept that is also used to send text messages and notifications to mobile numbers or email addresses from an application when a specific event is triggered. For instance, if you search for something in the online store and the required item is out of stock, you click on the “Notify me” bar to get an alert from the application when that item is available for purchase. These notifications from the applications are usually sent through webhooks.
Operation of Webhooks

# HIPAA(health insurance portability and accountability act)
- The HIPAA Privacy Rule provides federal protections for the individually identifiable health information held by covered entities and their business associates and gives patients an array of rights to that information. The Security Rule specifies a series of administrative, physical, and technical safeguards for covered entities and their business associates to use to ensure the confidentiality, integrity, and availability of electronically protected health information. (P.96/80)
- HIPAA(Health Insurance Portability and Accountability Act)/PHI (Protected Health Information)

# Sarbanes Oxley Act(SOX) 
- Enacted in 2002, the Sarbanes-Oxley Act is designed to protect investors and the public by increasing the accuracy and reliability of corporate disclosures

# NetBIOS Suffixes
==================
- NetBIOS name is a unique 16 character used to identify the network devices over TCP/IP.
00: Workstation Service (workstation name)
03: Windows Messenger service.
06: Remote Access Service.
20: File Service (also called Host Record)
21: Remote Access Service client.
1B: Domain Master Browser – Primary Domain Controller for a domain.
1D: Master Browser.

# STP Attack
In a Spanning Tree Protocol (STP) attack, attackers connect a rogue switch into the network to change the operation of the STP protocol and sniff all the network traffic. 
- STP is used in LAN-switched networks with the primary function of removing potential loops within the network. STP ensures that the traffic inside the network follows an optimized path to enhance network performance. 
- In this process, a switch inside the network is appointed as the root bridge. After the selection of the root bridge, other switches in the network connect to it by selecting a root port (the closest port to the root bridge). The root bridge is selected with the help of Bridge Protocol Data Units (BPDUs). BPDUs each have an identification number known as a BID or ID. These BIDs consist of the Bridge Priority and the MAC address. 
- By default, the value of the Bridge Priority is 32769. If an attacker has access to two switches, he/she introduces a rogue switch in the network with a priority lower than any other switch in the network. This makes the rogue switch the root bridge, thus allowing the attacker to sniff all the traffic flowing in the network.
- Attackers connect a rogue switch into the network to change the operations of the STP protocol and sniff all the network traffic.Attackers configure the rogue switch such that its priority is less than that of any other switch in the network, which makes it the root bridge, thus allowing the attackers to sniff all the traffic flowing in the network. (P.1167/1151)

# which of the following protocols can be used to secure an LDAP service against anonymous queries?
A. SSO 
B. RADIUS 
C. WPA
D. NTLM
## Answer: D
- CEH v11 page 493 (Use NTLM or any basic authentication mechanism to limit access to legitimate users only)
SMB
- LDAP Enumeration Countermeasures：By default, LDAP traffic is transmitted unsecured (Port 389); therefore, use Secure Sockets Layer (SSL) or STARTTLS technology to encrypt the traffic (Port 636). Use NTLM or any basic authentication mechanism to limit access to legitimate users. (P.494/478)
- Explanation: In a Windows network, nongovernmental organization ``(New Technology) local area network Manager (NTLM)`` could be a suite of Microsoft security protocolssupposed to produce authentication, integrity, and confidentiality to users.
- NTLM is that the successor to the authentication protocol in Microsoft local area networkManager (LANMAN), Associate in Nursing older Microsoft product. The NTLM protocol suite is enforced in an exceedingly Security Support supplier, which mixesthe local area network Manager authentication protocol, NTLMv1, NTLMv2 and NTLM2 Session protocols in an exceedingly single package. whether or not theseprotocols area unit used or will be used on a system is ruled by cluster Policy settings, that totally different|completely different} versions of Windows have differentdefault settings. 
- NTLM passwords area unit thought-about weak as a result of they will be brute-forced very simply with fashionable hardware.NTLM could be a challenge-response authentication protocol that uses 3 messages to authenticate a consumer in an exceedingly affiliation orientating setting(connectionless is similar), and a fourth extra message if integrity is desired.First, the consumer establishes a network path to the server and sends a NEGOTIATE_MESSAGE advertising its capabilities.Next, the server responds with CHALLENGE_MESSAGE that is employed to determine the identity of the consumer. 
- Finally, the consumer responds to thechallenge with Associate in Nursing AUTHENTICATE_MESSAGE.The NTLM protocol uses one or each of 2 hashed word values, each of that are keep on the server (or domain controller), and that through a scarcity of seasoningarea unit word equivalent, that means that if you grab the hash price from the server, you’ll evidence while not knowing the particular word. the 2 area unit the lmHash (a DES-based operate applied to the primary fourteen chars of the word born-again to the standard eight bit laptop charset for the language), and also the ntHash (MD4 of the insufficient endian UTF-16 Unicode password). each hash values area unit sixteen bytes (128 bits) every.The NTLM protocol additionally uses one among 2 a method functions, looking on the NTLM version.National Trust LanMan and NTLM version one use the DES primarily based LanMan a method operate (LMOWF), whereas National TrustLMv2 uses the NT MD4primarily based a method operate (NTOWF)

# Replay Attack
- Types of SDR-based attacks performed by attackers to break into an IoT environment: 
- Replay Attack This is the major attack described in IoT threats, in which attackers can capture the command sequence from connected devices and use it for later retransmission. An attacker can perform the below steps to launch a replay attack: o Attacker targets the specified frequency that is required to share information between devices
- After obtaining the frequency, the attacker can capture the original data when the commands are initiated by the connected devices
- Once the original data is collected, the attacker uses free tools such as URH (Universal Radio Hacker) to segregate the command sequence
- Attacker then injects the segregated command sequence on the same frequency into the IoT network, which replays the commands or captured signals of the devices

# Wired Equivalent Privacy (WEP) Encryption
WEP is a security protocol defined by the 802.11b standard; it was designed to provide a wireless LAN with a level of security and privacy comparable to that of a wired LAN.It has significant vulnerabilities and design flaws and can therefore be easily cracked. (P.2199/2183)


# Zig-Bee: 
- This is another short-range communication protocol based on the IEEE 203.15.4 standard. Zig-Bee is used in devices that transfer data infrequently at a low rate in a restricted area and within a range of 10–100 m.
- he 802.15.4 standard has a low data rate and complexity. The specification used in this standard is ZigBee, which transmits long-distance data through a mesh network. The specification handles applications with a low data rate of 250 Kbps, but its use increases battery life.
- 802.15.4 for Zigbee , bluetooth is 802.15.1
- The operating range of `LPWAN` technology varies from `a few kilometers in urban` areas to` over 10 km in rural` settings

# AirPcap ???
- was a specialized solution to do what you can do on Linux (injection/monitor mode). as far as I know you cannot on WINDOWS capture Wifi traffic without the outdated Aircap. Winpcap does not put the Wifi card into monitor mode on windows.
- apture is mostly limited by Winpcap and not by Wireshark. However, Wireshark includes Airpcap support, a special -and costly- set of WiFi hardware that supports WiFi traffic monitoring in monitor mode. In other words, it allows capturing WiFi network traffic in promiscuous mode on a WiFi network. However these cards have been discontinued and are deprecated, so they cannot capture traffic on networks running the latest WiFi standards (802.11ac)
- The AirPcap adapters from Riverbed Technology allow full raw 802.11 captures under Windows, including radiotap information. Note that the AirPcap adaptors are no longer being sold by Riverbed, as announced in their End-of-Availability (EOA) Notice on October 2, 2017.


# Tailgating Vs Piggybacking
- Tailgating" implies no consent (similar to a car tailgating another vehicle on a road), while "piggybacking" usually implies consent of the authorized person
- Piggybacking - An authorized person intentionally or unintentionally allows an unauthorized person to pass through a secure door e.g., “I forgot my ID badge at home. Please help me”.
- Tailgating - The attacker, wearing a fake ID badge, enters a secured area by closely following an authorized person through a door that requires key access.

# Wireless Security Tools - Wi-Fi IPSs
- Wi-Fi IPSs block wireless threats by automatically scanning, detecting, and classifying unauthorized wireless access and rogue traffic to the network, thereby preventing neighboring users or skilled hackers from gaining unauthorized access to the Wi-Fi networking resources. (P.2374/2358)
-  wireless intrusion prevention system (WIPS) is a network device that monitors the radio spectrum to detect APs (intrusion detection) without the host’s permission in nearby locations. It can also implement countermeasures automatically. WIPSs protect networks against wireless threats and provide administrators the ability to detect and prevent various network attacks.
EC-Council C|EH v11 Courseware, page 2369

# You are tasked to configure the DHCP server to lease the last 100 usable IP addresses in subnet 10.1.4.0/23.
Which of the following IP addresses could be leased as a result of the new configuration?
A. 10.1.255.200
B. 10.1.4.156
C. 10.1.4.254
D. 10.1.5.200

- To answer this question, you need to find the range of addresses in the subnet, which typically then means you need to calculate the subnet ID and subnet broadcast address. With a subnet ID/mask of 10.1.4.0/23, the mask converts to 255.255.254.0.
- To find the subnet broadcast address, following the decimal process described in this chapter, you can copy the subnet ID’s first two octets because the mask’s value is 255 in each octet. You write a 255 in the fourth octet because the mask has a 0 on the fourth octet. In octet 3, the interesting octet, add the magic number (2) to the subnet ID’s value (4), minus 1, for a value of 2 + 4 – 1 = 5. (The magic number in this case is calculated as 256 – 254 = 2.) That makes the broadcast address 10.1.5.255. The last usable address is 1 less: 10.1.5.254. The range that includes the last 100 addresses is 10.1.5.155 – 10.1.5.254.
- 10.1.4.0/23 = 10.1.4.0 255.255.254.0
- Range is 10.1.4.0 - 10.1.5.255
- 10.1.4.0 = network address
- 10.1.5.255 = broadcast address

![subnet.jpg](:/89b72f949b2d42d284f3abe2a896c01f)

# Hping2 Scan Mode

Mode
default mode TCP
- 0 --rawip RAW IP mode
- 1 --icmp ICMP mode
- 2 --udp UDP mode
- 8 --scan SCAN mode.
Example: `hping --scan 1-30,70-90 -S www.target.host`
- 9 --listen listen mode
- Hping performs an ICMP ping scan by specifying the argument -1 in the command line. You may use --ICMP or -1 as the argument in the command line. By issuing the above command, hping sends an ICMP echo request to x.x.x.x and receives an ICMP reply similar to a ping utility.


# AAA Protocol
- The Diameter protocol is also an AAA protocol like RADIUS and TACACS+, but it is designed to overcome some of the limitations of RADIUS, particularly in terms of security and scalability. Diameter is an IETF standard protocol that supports a wide range of authentication, authorization, and accounting (AAA) applications, including network access and mobile IP. It has features such as Transport Layer Security (TLS) encryption, dynamic discovery of servers, and a flexible message structure that allow for greater security and scalability. Therefore, Diameter can also handle the requirement described in the question
- The Diameter protocol is also an AAA protocol like RADIUS and TACACS+, but it is designed to overcome some of the limitations of RADIUS, particularly in terms of security and scalability. Diameter is an IETF standard protocol that supports a wide range of authentication, 
-   authorization, and accounting (AAA) applications, including network access and mobile IP. It has features such as Transport Layer Security (TLS) encryption, dynamic discovery of servers, and a flexible message structure that allow for greater security and scalability. Therefore, Diameter can also handle the requirement described in the question
-   Remote Authentication Dial-In User Service (RADIUS) is an authentication protocol that provides centralized authentication, authorization, and accounting (AAA) for the remote access servers to communicate with the central server
Radius Authentication Steps: 1. The client initiates the connection by sending an Access-Request packet to the server
2. The server receives the access request from the client and compares the credentials with the ones stored in the database. If the provided information matches, then it sends the Accept-Accept message along with the Access-Challenge to the client for additional authentication, otherwise it sends back the Accept-Reject message

# Anomaly Detection 
- Anomaly detection, or “not-use detection,” differs from signature recognition. An anomaly is detected when an event occurs outside the tolerance threshold of normal traffic.Therefore, `any deviation from regular use is an attack`. Anomaly detection detects intrusions based on the fixed behavioral characteristics of the users and components in a computer system. (P.1480/1464)

# Snort

- `Intrusion Detection Tools: Snort`
- Snort is an open-source network intrusion detection system, capable of performing real-time traffic analysis and packet logging on IP networks.
- Uses of Snort:1. Straight packet sniffer such as tcpdump2. Packet logger (useful for network traffic debugging, etc.)3. Network intrusion prevention system (P.1518/1502)

# You have compromised a server and successfully gained a root access. You want to pivot and pass traffic undetected over the network and evade any possible
Intrusion Detection System. What is the best approach?
A. Use Alternate Data Streams to hide the outgoing packets from this server.
B. Use HTTP so that all traffic can be routed vis a browser, thus evading the internal Intrusion Detection Systems.
C. Install Cryptcat and encrypt outgoing packets from this server. (Correct Answer)
D. Install and use Telnet to encrypt all outgoing traffic from this server.

- Employ a crypter such as BitCrypter to encrypt the Trojan to evade detection by firewalls/IDS. (P.904/888)
- CryptCat is a simple Unix utility which reads and writes data across network connections, using TCP or UDP protocol while encrypting the data being transmitted.

# Non-repudiation 
- assurance that someone cannot deny the validity of something.

# The security administrator of ABC needs to permit Internet traffic in the host 10.0.0.2 and UDP traffic in the host 10.0.0.3. He also needs to permit all FTP traffic to the rest of the network and deny all other traffic. After he applied his ACL configuration in the router, nobody can access the ftp, and the permitted hosts cannot access the Internet. According to the next configuration, what is happening in the network?

A. The ACL 104 needs to be first because is UDP
B. The first ACL is denying all TCP traffic and the other ACLs are being ignored by the router (Correct Answer)
C. The ACL for FTP must be before the ACL 110
D. The ACL 110 needs to be changed to port 80


# Which access control mechanism allows for multiple systems to use a central authentication server (CAS) that permits users to authenticate once and gain access to multiple systems?
A. Role Based Access Control (RBAC)
B. Discretionary Access Control (DAC)
C. Single sign-on (correct Answer)
D. Windows authentication

- Single Sign-on (SSO) authentication processes permit a user to sign into an application using a single set of credentials and use the same login session to access multiple applications irrespective of domains or platforms
- The communication between these applications can be done through SAML messages SAML messages are encrypted using Base64 encoding and can be easily decrypted to extract the content of messages Attackers use tools such as SAML Raider to bypass SAM-based SSO authentication

# Internet Protocol Security (IPsec) 
- uses Encapsulation Security Payload (ESP), Authentication Header (AH), and Internet Key Exchange (IKE) to `secure communication between virtual private network (VPN)` end points by authenticating and encrypting each IP packet of a communication session.
- Transport Mode - In the transport mode (also ESP), IPsec encrypts only the payload of the IP packet, leaving the header untouched. It authenticates two connected computers and provides the option of encrypting data transfer. (P.1464/1448)

# Shell Shock Vulnerability (CVE-2014-6271.)
This vulnerability impacts the Bourne Again Shell "Bash". Bash is not usually available through a web application but can be indirectly exposed through a Common Gateway Interface "CGI".


# Firewalk has just completed the second phase (the scanning phase) and a technician receives the output shown below. What conclusions can be drawn based on these scan results?

TCP port 21 no response -

TCP port 22 no response -
TCP port 23 Time-to-live exceeded
A. The lack of response from ports 21 and 22 indicate that those services are not running on the destination server
B. The scan on port 23 was able to make a connection to the destination host prompting the firewall to respond with a TTL error
C. The scan on port 23 passed through the filtering device. This indicates that port 23 was not blocked at the firewall (Correct Answer)
D. The firewall itself is blocking ports 21 through 23 and a service is listening on port 23 of the target host

- The entire route is determined using any of the traceroute techniques available
A packet is sent with the TTL equal to the distance to the target
If the packet times out, it is resent with the TTL equal to the distance to the target minus one.
If an ICMP type 11 code 0 (Time-to-Live exceeded) is received, the packet was forwarded and so the port is not blocked.
- If no response is received, the port is blocked on the gateway.
- Firewall Evasion Techniques
Firewall Identification - Firewalking
a method of collecting information about remote networks behind firewalls. Technique that uses TTL values to determine gateway ACL filters and map networks by analyzing the IP packet response. (P.1567/1551)
`Nmap -O -sA <target IP address>`

# N-tier application architecture
- N-tier architecture would involve dividing an application into three different tiers.
- Presentation tier - To translate tasks and results to something the user can understand
- Logic tier - Coordinates the application, processes commands, makes logical decisions and evaluations, and performs calculations. It also moves and processes data between the two surrounding layers.
- Data tier - Here information is stored and retrieved from a database or file system.

# Phishing Vs Pharming
- Computer-based Social Engineering: Phishing
Pharming is a social engineering technique in which the attacker executes malicious programs on a victim’s computer or server, and when the victim enters any URL or domain name, it automatically redirects the victim’s traffic to an attacker-controlled website.This attack is also known as “Phishing without a Lure.”
- Pharming attack can be performed in two ways: DNS Cache Poisoning and Host File Modification
- Phishing is a technique in which an attacker sends an email or provides a link falsely claiming to be from a legitimate site to acquire a user’s personal or account information. The attacker registers a fake domain name, builds a lookalike website, and then mails the fake website’s link to users. When a user clicks on the email link, it redirects them to the fake webpage, where they are lured into sharing sensitive details such as their address and credit card information. Some of the reasons behind the success of phishing scams include users’ lack of knowledge, being visually deceived, and not paying attention to security indicators.
-  The Pharming, also known as domain spoofing, is an advanced form of phishing in which the attacker redirects the connection between the IP address and its target server. The attacker may use cache poisoning (modifying the Internet address to that of a rogue address) to do so. When the users type in the Internet address, it redirects them to a rogue website that resembles the original.

# Virus Detection Methods

1. Scanning: Once a virus is detected, it is possible to write scanning programs that look for signature string characteristics of the virus

2. Integrity Checking: Integrity checking products work by reading the entire disk and recording integrity data that act as a signature for the files and system sectors

3. Interception: The interceptor monitors the operating system requests that are written to the disk

4. Code Emulation: In code emulation techniques, the antivirus executes the malicious code inside a virtual machine to simulate CPU and memory activities These techniques are considered very effective in dealing with encrypted and polymorphic viruses if the virtual machine mimics the real machine

5. Heuristic Analysis: Heuristic analysis can be static or dynamic In static analysis, the antivirus analyses the file format and code structure to determine if the code is viral In dynamic analysis, the antivirus performs a code emulation of the suspicious code to determine if the code is viral

# Packet Sniffer

- Sniffers operate at the data link layer and can capture packets. (P.1105)
- The data link layer is the second layer of the OSI model. In this layer, data packets are encoded and decoded into bits. Sniffers operate at the data link layer and can capture packets from this layer. Networking layers in the OSI model are designed to work independently of each other; thus, if a sniffer sniffs data in the data link layer, the upper OSI layers will not be aware of the sniffing.

# You are a security officer of a company. You had an alert from IDS that indicates that one PC on your Intranet is connected to a blacklisted IP address (C2 Server) on the Internet. The IP address was blacklisted just before the alert. You are starting an investigation to roughly analyze the severity of the situation. Which of the following is appropriate to analyze?
A. IDS log
B. Event logs on domain controller
C. Internet Firewall/Proxy log. (Correct Answer)
D. Event logs on the PC


# Yagi antenna
- also called Yagi-Uda antenna, is a unidirectional antenna commonly used in communications at a frequency band of 10 MHz to VHF and UHF.

# Wrieless Range

802.11a Range 35- 100 meters
802.11b Range 35- 140 meters
802.11g Range 38- 140 meters
802.16 (WiMAX) Range 1- 6 miles

# USB Dumper 
- is an simple yet very reliable software solution designed to provide you with the ability to automatically and silently copy data from a flash drive that is connected to your PC, without prompting you for any confirmation.

# Honeypots

## Detecting and Defeating Honeypots - Detecting the presence of Honeyd Honeypot
-  An attacker can identify the presence of a `honeyd honeypot` by performing `time-based TCP fingerprinting method (SYN proxy behavior)`
-  Honeyd is a widely used honeypot daemon.This honeyd honeypot can respond to a remote attacker who tries to contact the SMTP service with fake responses. An attacker can identify the presence of honeyd honeypot by performing time-based TCP fingerprinting methods (SYN proxy behavior). (P.1601/5885)

## Detecting Honeypots running on VMware
- Observe the IEEE standards for the current range of MAC addresses assigned to VMWare Inc

## Detecting the presence of Snort_inline Honeypot:
- `Analyze the outgoing packets by capturing the Snort_inline modified packets` through another host system and `identifying the packet modification`

# Detecting the presence of Honeyd Honeypot:
- Perform time-based TCP Finger printing methods (SYN Proxy behavior)

# Detecting the presence of Sebek-based Honeypots:
- Sebek logs everything that is accessed via read() before transferring it to the network, causing the congestion effect. `Analyze the congestion in the network layer`

# `-sA` (TCP ACK scan)
This scan is different than the others discussed so far in that it never determines open (or even open|filtered) ports. It is used to `map out firewall rulesets, determining whether they are stateful or not` and which ports are filtered.

The ACK scan probe packet has only the ACK flag set (unless you use --scanflags). When scanning `unfiltered` systems, open and closed ports will both `return a RST packet`. Nmap then labels them as unfiltered, meaning that they are reachable by the ACK packet, but `whether they are open or closed is undetermined`. Ports that `don't respond`, or send certain ICMP error messages back (type 3, code 0, 1, 2, 3, 9, 10, or 13), are labeled `filtered`.
- ACK Flag Probe scan
ACK flag probe scanning can also be used to check the filtering system of a target.Attackers send an ACK probe packet with a random sequence number, and no response implies that the port is filtered (stateful firewall is present), whereas an RST response means that the port is not filtered.
`Nmap -sA -v <target IP address>` (P.311/295)

# Reverse Engineering Mobile Applications
Reverse engineering is the process of analyzing and extracting the source code of a software or application, and if needed, regenerating it with required modifications.Reverse engineering is used to disassemble a mobile application to analyze its design flaws and fix any bugs that are residing in it

# ABAC
-  No proper attribute-based access control (ABAC) validation allows attackers to gain unauthorized access to API objects or perform actions such as viewing, updating, or deleting.
-  `No ABAC Validation` - No proper attribute-based access control (ABAC) validation allows attackers to gain unauthorized access to API objects or perform actions such as viewing, updating, or deleting.
- `Business Logic Flaws` - Many APIs come with vulnerabilities in business logic .
Allow attackers to exploit legitimate workflows for malicious purposes.
- `Improper Use of CORS` - Cross-origin resource sharing (CORS) is a mechanism that enables the web browser to perform cross-domain requests; improper implementations of CORS can cause unintentional flaws .
Using the “Access-Control-Allow-Origin” header for allowing all origins on private APIs can lead to hotlinking.
- `Code Injections` - If the input is not sanitized, attackers may use code injection techniques such as SQLi and XSS to add malicious SQL statements or code to the input fields on the API.Allow attackers to steal critical information such as session cookies and user credentials.

# Evilginx
Evilginx is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. It's core runs on Nginx HTTP server, which utilizes proxy_pass and sub_filter to proxy and modify HTTP content, while intercepting traffic between client and server.

# Phishing Tools
Phishing tools can be used by attackers to generate fake login pages to capture usernames and passwords, send spoofed emails, and obtain the victim’s IP address and session cookies.This information can further be used by the attacker, who will use it to impersonate a legitimate user and launch further attacks on the target organization.
`Tools: ShellPhish / PhishX / Modlishka / Trape / Evilginx`

# Cloud Computing Threats - Lock-in
Lock-in reflects the inability of the client to migrate from one CSP to another or in-house systems owing to the lack of tools, procedures, standard data formats, applications, and service portability. This threat is related to the inappropriate selection of a CSP, incomplete and non-transparent terms of use, lack of standard mechanisms, etc. (P.2884/2868)
- CEHv11 Cloud Computing Module Cloud Computing Threats (Page:2860)

# A Web page with an ".stm" extension 
- is an .HTM file that contains server side includes (SSI). These "includes" are directives that are processed by the Web server when the page is accessed by a user. They are used to generate dynamic content. SSI Web pages can be viewed as a standard HTML page in any browser.
- Defend Against Injection Attacks - Server-Side Include Injection
Avoid using pages with file name extensions such as .stm, .shtm, and .shtml to prevent attacks.
- n order for a web server to recognize an SSI-enabled HTML file and therefore carry out these instructions, either the filename should end with a special extension, by default .shtml, .stm, .shtm, or, if the server is configured to allow this, set the execution bit of the file

# Ciphers - CAST128
- CAST- 128, also called CAST5, is a symmetric-key block cipher having a classical 12-or 16-round Feistel network with a block size of 64 bits. CAST- 128 components include large 8×32- bit S- boxes (S1, S2, S3, S4) based on bent functions, modular addition and subtraction, key-dependent rotation, and XOR operations. (P.3035/3019)
- CAST-128, also called CAST5, is a symmetric-key block cipher having a classical 12-or 16-round Feistel network with a block size of 64 bits.

# IoTSeeker (Tool)
- allows you to scan your network for known device types that could be used as unwilling participants in a distributed denial-of-service attack. With this tool you can find out if you have connected “Things” which are using the default factory password leaving them potentially vulnerable to a hostile takeover. Use the local scan output to determine which devices need to be secured or removed from the network.
- IoTSeeker to discover IoT devices that are using default credentials and are vulnerable to various hijacking attacks. IoTSeeker will scan a network for specific types of IoT devices to detect whether they are using the default, factory-set credentials. IoTSeeker focuses on HTTP/HTTPS services. (P.2633/2617)
- `IoT Inspector` - app for general management, monitor, maintenance of IoT devices
- `AT&T IoT Platform` - app for general management, monitor, maintenance of IoT devices
- `Azure IoT Central` - app for general management, monitor, maintenance of IoT devices

# Objectives of Footprinting
Draw Network Map - Combining footprinting techniques with tools such as Tracert allows the attacker to create diagrammatic representations of the target organization’s network presence. Specficially, it allows attackers to draw a map or outline of the target organization’s network infrastructure to know about the actual environment that they are going to break into. These network diagrams can guide the attacker in performing an attack. (P.114/98)


# Bob wants to ensure that Alice can check whether his message has been tampered with. He creates a checksum of the message and encrypts it using asymmetric cryptography.
What key does Bob use to encrypt the checksum for accomplishing this goal?
A. Alice's public (Correct answer)
B. His own public key
C. His own private key Most Voted
D. Alice's private key

- Encrypt the message -> Alice's public key
- Encrypt the checksum -> His own private key
-  you use your private key foro sign a message (digital signature), but you use the public key of the destinatary for encrypt the message!
-  Bob will digitally sign the message using his private key.
- Bob will encrypt the message using Alice's public key - So only Alice can decrypt the message.
The question talks about encryption.
Hence Answer is A - Alice's public key

# Which of the following LM hashes represent a password of less than 8 characters? (Choose two):

A. BA810DBA98995F1817306D272A9441BB
B. 44EFCE164AB921CQAAD3B435B51404EE
C. 0182BD0BD4444BF836077A718CCDF409
D. CEC52EB9C8E3455DC2265B23734E0DAC
E. B757BF5C0D87772FAAD3B435B51404EE
F. E52CAC67419A9A224A3B108F3FA6CB6D

- Any password that is shorter than 8 characters will result in the hashing of 7 null bytes, yielding the constant value of 0xAAD3B435B51404EE, hence making it easy to identify short passwords on sight.

# 73. The change of a hard drive failure is once every three years. The cost to buy a new hard drive is $300. It will require 10 hours to restore the OS and software to the new hard disk. It will require a further 4 hours to restore the database from the last backup to the new hard disk. The recovery person earns $10/hour. Calculate the SLE, ARO, and ALE. Assume the EF = 1(100%) .

What is the closest approximate cost of this replacement and recovery operation per year?

$1320
$440
$100
$146
```
- Wouldn't it be 146?

First examine the EF = 100
Hard drive fails every 3 years so divide 100/3 which = 33.333... or 33% (rounded)

There's a 33% chance the hard drive will fail each year and it will definitely fail within 3 years.

So ARO = 33% or .33

And SLE = 300 + 14 * 10
($300 for the hard drive plus $14*10 for the worker)

Then we have .33*(300+14*10)

Remember PEMDAS?
(Parenthesis, Exponent, Multiply, Divide, Add, Subtract)

So we multiply what's in the parenthesis first (14*10) which = 140

Then we add what's left in the parenthesis (300 + 140) which = 440

Lastly we multiply .33*440 which = 145.2

Closest answer is 146.

If you multiply 146 * 3 (for 3 years) it = 438, close to 440.

If I'm off please let me know.
```
## Annualized Loss Expectancy (ALE)

- Annual cost of a loss due to a risk.
- Used often in risk analysis and business impact analysis
- 📝 `ALE = ARO (Annual rate of occurrence) x SLE (Single loss expectancy)`
- **Annual rate of occurrence (ARO)**
  - E.g. if it occurs every month than it's 12, if it's every second year than it's 1/2
- **Single loss expectancy (SLE)**
  - Total loss value for a single asset after an exploit
  - `SLE (Single Loss Expectancy) = AV (Asset Value) x EF (Exposure Factor)`
  - **Asset value (AV)**
    - How much would it take to replace 1 asset
    - Including product prices, manhours etc.
  - **Exposure Factor (EF)**
    - Percentage of asset value lost if threat is realized
    - Usually a subjective value
- E.g. an asset is valued at $100,000, and the Exposure Factor (EF) for this asset is 25%. The single loss expectancy (SLE) then, is 25% * $100,000, or $25,000.
- **Total cost of ownership (TCO)**
  - Total cost of a mitigating safeguard
- **Return on Investment (ROI)**
  - Amount of money saved by implementing a safeguard.
  - 💡 Good choice if annual Total Cost of Ownership (TCO) is less than Annualized Loss Expectancy (ALE); poor choice otherwise

# Fred is the network administrator for his company. Fred is testing an internal switch.

From an external IP address, Fred wants to try and trick this switch into thinking it already has established a session with his computer .

How can Fred accomplish this?

- Fred can accomplish this by sending an IP packet with the RST/SIN bit and the source address of his computer.
- He can send an IP packet with the SYN bit and the source address of his computer.
- Fred can send an IP packet with the ACK bit set to zero and the source address of the switch.
- Fred can send an IP packet to the switch with the ACK bit and the source address of his machin (correct answer)
