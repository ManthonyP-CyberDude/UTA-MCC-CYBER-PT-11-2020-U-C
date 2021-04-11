## Unit 11 Submission File: Network Security Homework 

### Part 1: Review Questions 

#### Security Control Types

The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set  of defense tactics.

1. Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?

    Answer: Physical Controls

2. Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?

    Answer: Management Controls

3. Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?

    Answer: Data Protections Access Control

#### Intrusion Detection and Attack indicators

1. What's the difference between an IDS and an IPS?

    Answer:Answer: IDS - Analyzes and monitors network traffic for signs of intrusion.
           IPS - Proactively denies network traffic based on a sercurity profile, if that packet represents a known security threat.

2. What's the difference between an Indicator of Attack and an Indicator of Compromise?
    
    Indicator of Attack: Focuses on detecting the intent of what an attacker is trying to accomplish.
    Indicator of Compromise: Used by legacy endpoint detection solutions. 

   

#### The Cyber Kill Chain

Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.

1. Stage 1: Reconnaissance -The attacker/intruder chooses their target. Then they conduct an in-depth research on this target to identify its vulnerabilities that can be    exploited.

2. Stage 2: Weaponization - n this step, the intruder creates a malware weapon like a virus, worm or such in order to exploit the vulnerabilities of the target. Depending on the target and the purpose of the attacker, this malware can exploit new, undetected vulnerabilities (also known as the zero-day exploits) or it can focus on a combination of different vulnerabilities.

3. Stage 3: Delivery - This step involves transmitting the weapon to the target. The intruder / attacker can employ different methods like USB drives, e-mail attachments and websites for this purpose.

4. Stage 4: Exploitation - In this step, the malware starts the action. The program code of the malware is triggered to exploit the target’s vulnerability/vulnerabilities.

5. Stage 5: Installation - In this step, the malware installs an access point for the intruder / attacker. This access point is also known as the backdoor.

6. Stage 6: Command and Control - The malware gives the intruder / attacker access in the network/system.

7. Stage 7: Actions on Objectives - Once the attacker / intruder gains persistent access, they finally take action to fullfil their purpose, such as encryption for ransom, data exfiltration or even data destruction.


#### Snort Rule Analysis

Use the Snort rule to answer the following questions:

Snort Rule #1

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
```

1. Break down the Sort Rule header and explain what is happening.

   Answer: alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820";  - It is scanning ET SCAN Potential VNC Scan Ports: 5800 - 5820

2. What stage of the Cyber Kill Chain does this alert violate?

   Answer: Weaponization

3. What kind of attack is indicated?

   Answer: Emerging Threats were found. 

Snort Rule #2

```bash
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)
```

1. Break down the Sort Rule header and explain what is happening.

   Answer: alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any: It downloaded a dll file from http.

2. What layer of the Defense in Depth model does this alert violate?

   Answer: it shows a layer of Defense. 

3. What kind of attack is indicated?

   Answer: Ddos attack

Snort Rule #3

- Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the `msg` in the Rule Option.

    Answer: alert tcp any any -> any [44] (msg: "Sample alert"; sid: 1000001; rev:1; )

### Part 2: "Drop Zone" Lab

#### Log into the Azure `firewalld` machine

Log in using the following credentials:

- Username: `sysadmin`
- Password: `cybersecurity`

#### Uninstall `ufw`

Before getting started, you should verify that you do not have any instances of `ufw` running. This will avoid conflicts with your `firewalld` service. This also ensures that `firewalld` will be your default firewall.

- Run the command that removes any running instance of `ufw`.

    ```bash
    $ <sudo ufw reset>
    ```

#### Enable and start `firewalld`

By default, these service should be running. If not, then run the following commands:

- Run the commands that enable and start `firewalld` upon boots and reboots.

    ```bash
    $ <sudo ufw enable>
    $ <>
    ```

  Note: This will ensure that `firewalld` remains active after each reboot.

#### Confirm that the service is running.

- Run the command that checks whether or not the `firewalld` service is up and running.

    ```bash
    $ <sudo ufw status>
    ```


#### List all firewall rules currently configured.

Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by not doing double work.

- Run the command that lists all currently configured firewall rules:

    ```bash
    $ <sudo ufw status>
    ```

- Take note of what Zones and settings are configured. You many need to remove unneeded services and settings.

#### List all supported service types that can be enabled.

- Run the command that lists all currently supported services to see if the service you need is available

    ```bash
    $ <sudo firewall-cmd --get-services>
    ```

- We can see that the `Home` and `Drop` Zones are created by default.


#### Zone Views

- Run the command that lists all currently configured zones.

    ```bash
    $ <sudo firewall-cmd --list-all-zones>
    ```

- We can see that the `Public` and `Drop` Zones are created by default. Therefore, we will need to create Zones for `Web`, `Sales`, and `Mail`.

#### Create Zones for `Web`, `Sales` and `Mail`.

- Run the commands that creates Web, Sales and Mail zones.

    ```bash
    $ <sudo firewall-cmd --new-zone+zone-Web>
    $ <sudo firewall-cmd --new-zone+zone-Sales>
    $ <sudo firewall-cmd --new-zone+zone-Mail>
    ```

#### Set the zones to their designated interfaces:

- Run the commands that sets your `eth` interfaces to your zones.

    ```bash
    $ <sudo firewall-cmd --zone=Web --chang-interface=eth1>
    $ <sudo firewall-cmd --zone=Sales --chang-interface=eth1>
    $ <sudo firewall-cmd --zone=Mail --chang-interface=eth1>
    $ <sudo firewall-cmd --zone=Public --chang-interface=eth1>
    ```

#### Add services to the active zones:

- Run the commands that add services to the **public** zone, the **web** zone, the **sales** zone, and the **mail** zone.

- Public:

    ```bash
    $ <sudo firewall-cmd --zone=public --add-service=smtp>
    $ <sudo firewall-cmd --zone=public --add-service=http>
    $ <sudo firewall-cmd --zone=public --add-service=https>
    $ <sudo firewall-cmd --zone=public --add-service=pop3>

    
    ```

- Web:

    ```bash
    $ <sudo firewall-cmd --zone=web --add-service=http>
    ```

- Sales

    ```bash
    $ <sudo firewall-cmd --zone=sales --add-service=https>
    ```

- Mail

    ```bash
   $ <sudo firewall-cmd --zone=mail --add-service=smtp>
$ <sudo firewall-cmd --zone=mail --add-service=pop3>

    
    ```

- What is the status of `http`, `https`, `smtp` and `pop3`? 
    These services are running.

#### Add your adversaries to the Drop Zone.

- Run the command that will add all current and any future blacklisted IPs to the Drop Zone.

     ```bash
    $ <sudo firewall-cmd --permanent --zone=drop --add-source=10.208.56.23>
    $ <sudo firewall-cmd --permanent --zone=drop --add-source=135.95.103.76>
    $ <sudo firewall-cmd --permanent --zone=drop --add-source=76.34.169.118>

    ```

#### Make rules permanent then reload them:

It's good practice to ensure that your `firewalld` installation remains nailed up and retains its services across reboots. This ensure that the network remains secured after unplanned outages such as power failures.

- Run the command that reloads the `firewalld` configurations and writes it to memory

    ```bash
    $ <sudo firewall-cmd--reload>
    ```

#### View active Zones

Now, we'll want to provide truncated listings of all currently **active** zones. This a good time to verify your zone settings.

- Run the command that displays all zone services.

    ```bash
   $ <sudo firewall-cmd --get-active-zones>
    ```


#### Block an IP address

- Use a rich-rule that blocks the IP address `138.138.0.3`.

    ```bash
   $ <sudo firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="138.138.0.3" reject'>
    ```

#### Block Ping/ICMP Requests

Harden your network against `ping` scans by blocking `icmp ehco` replies.

- Run the command that blocks `pings` and `icmp` requests in your `public` zone.

    ```bash
    $ <sudo firewall-cmd --zone=public --add-icmp-block=echo-reply --add-icmp-block=echo-request>
    ```

#### Rule Check

Now that you've set up your brand new `firewalld` installation, it's time to verify that all of the settings have taken effect.

- Run the command that lists all  of the rule settings. Do one command at a time for each zone.

    ```bash
$ <sudo firewall-cmd --zone=public --list-all>
$ <sudo firewall-cmd --zone=sales --list-all>
$ <sudo firewall-cmd --zone=mail --list-all>
$ <sudo firewall-cmd --zone=web --list-all>
$ <sudo firewall-cmd --permanent --zone=drop --list-all>

    ```

- Are all of our rules in place? If not, then go back and make the necessary modifications before checking again.


Congratulations! You have successfully configured and deployed a fully comprehensive `firewalld` installation.

---

### Part 3: IDS, IPS, DiD and Firewalls

Now, we will work on another lab. Before you start, complete the following review questions.

#### IDS vs. IPS Systems

1. Name and define two ways an IDS connects to a network.

   Answer 1:  Network intrusion detection systems (NIDS) - Deployed or placed at strategic points throughout the network. Intended to cover those places where traffic is most likely to be vulnerable to attack. 

   Answer 2: Host-based intrusion detection systems (HIDS) - Runs on all devices in the network with access to the internet and other parts of the enterprise network. 

2. Describe how an IPS connects to a network.

   Answer: An intrusion prevention system will work by scanning through all network traffic. To do this, an IPS tool will typically sit right behind a firewalls actiing as an additional layer that will observe events for malicious contect. In this way, IPS tools are placed in direct communication paths between a system and network, enabling  the tool to analyze network traffic. 

3. What type of IDS compares patterns of traffic to predefined signatures and is unable to detect Zero-Day attacks?

   Answer: IDS is able to kick an offending user off the netowrk and send an alert to security personnel. Despite its benefits, including in-depth network traffic analysis and attack detection, an IDS has inherent drawbacks. Because it uses previously known intrusion signatures to locate attacks, newly discovered (i.e., zero-day) threats can remain undetected. 

4. Which type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?

   Answer: Anomaly-based detection

#### Defense in Depth

1. For each of the following scenarios, provide the layer of Defense in Depth that applies:

    1.  A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.

        Answer: Avoid sharing professional information on social media. 

    2. A zero-day goes undetected by antivirus software.

        Answer: When a user installs anti-virus software. Generally, the program is an older/basic version of the software that requires updates to protect the system. A zero-day attack/exploit occurs when a cyberattacker compromises the system since it hasn't updated to its latest protection library. You could also think about the hardware itself; a new computer without installed protections is vulnerable to any form of exploit until it's updated appropriately. Here are several defensive measures which can protect you against zero-day attacks that are zero-day protection integrated with Microsoft Windows 2010, Next-Generation Antivirus (NGAV), patch management, and putting in place an incident response plan.

    3. A criminal successfully gains access to HR’s database.

        Answer: 1. Usa a firewall 2. Install antivirus software 3. Install an anti-spyware package 4. Use complex passwords 5. Keep your OS, apps and browser up to date 6. Use encryption.

    4. A criminal hacker exploits a vulnerability within an operating system.

        Answer: 1. Keep your anti-virus, software, and operating system up to date 2. Look before you leap 3. Don't click on emails or download attachments from unknown senders 4. Update patches.

    5. A hacktivist organization successfully performs a DDoS attack, taking down a government website.

        Answer: First line of defense should be a Web applicaton firewall (WAF). This device can protect you site against the most vicious DDOS threst. These firewalls with DDos support redirects malicious traffic to other content delivery networks, distributing the load away from the server. You can user your firewall in conjudtion with a website scanner or some other intrusion detection system to identify malicious bot traffic and remove malware promptly. 

    6. Data is classified at the wrong classification level.

        Answer: Data is classified according to its sensitivity level-high, medium, or low. A best practice is to user labels for each sensitivity level that make sense for your organization. 

    7. A state sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.

        Answer: Avoid acquiring technology from companies based in nations that pose a threat;  1. Isolate internal networks from the internet 2. Share cyberthreat information with other organizations 3. Enhance employee cybersecurity awareness programs, including testing worker knowledge of best IT ssecurity practices. 

8. Name one method of protecting data-at-rest from being readable on hard drive.

    Answer: AES

9. Name one method to protect data-in-transit.

    Answer: Symmetric encryption with a set session key

10. What technology could provide law enforcement with the ability to track and recover a stolen laptop.

   Answer: Stepss in a successful recovery
    1. The owner of the laptop must contact law enforcement and file a theft report. Log into the Absolute Customer Center and report your laptop as missing.
    2. The ATR team uses advanced forensice technology to locate the laptop and possibly identify who has it. They share this information with local law enforcement, who recover the computer. 3. The laptop is returned to you ASAP.

11. How could you prevent an attacker from booting a stolen laptop using an external hard drive?

    Answer: Password encryption. If someone has physical possession of your laptop, passwords are not much help. They can use a guest account (unless you disabled it), boot your PC with a different operating system (linux), or remove the hard drive and install it in another PC. Encryption is the only viable defence. 


#### Firewall Architectures and Methodologies

1. Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.

  Answer: Circuit-filtering Firewall/Statefull Firewalls

2. Which type of firewall considers the connection as a whole? Meaning, instead of looking at only individual packets, these firewalls look at whole streams of packets at one time.

  Answer: Next Generation Firewall

3. Which type of firewall intercepts all traffic prior to being forwarded to its final destination. In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it?

  Answer: Packet Filtering Firewall


4. Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type- all without opening the packet to inspect its contents?

  Answer: Packet Filtering Firewall


5. Which type of firewall filters based solely on source and destination MAC address?

  Answer: Packet Filtering Firewall



### Bonus Lab: "Green Eggs & SPAM"
In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker.
 
- You will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California.
 
- As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review.
 
- You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling **Threat Intelligence** as part of your incident report.

#### Threat Intelligence Card

**Note**: Log into the Security Onion VM and use the following **Indicator of Attack** to complete this portion of the homework. 

Locate the following Indicator of Attack in Sguil based off of the following:

- **Source IP/Port**: `188.124.9.56:80`
- **Destination Address/Port**: `192.168.3.35:1035`
- **Event Message**: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`

Answer the following:

1. What was the indicator of an attack?
   - Hint: What do the details of the reveal? 

    Answer: 


2. What was the adversarial motivation (purpose of attack)?

    Answer: 

3. Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table.

| TTP | Example | Findings |
| --- | --- | --- | 
| **Reconnaissance** |  How did they attacker locate the victim? | 
| **Weaponization** |  What was it that was downloaded?|
| **Delivery** |    How was it downloaded?|
| **Exploitation** |  What does the exploit do?|
| **Installation** | How is the exploit installed?|
| **Command & Control (C2)** | How does the attacker gain control of the remote machine?|
| **Actions on Objectives** | What does the software that the attacker sent do to complete it's tasks?|


    Answer: 


4. What are your recommended mitigation strategies?


    Answer: 


5. List your third-party references.

    Answer: 


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.
