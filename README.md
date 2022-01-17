# Notes on Cybersecurity - Defending and Securing Systems

## Best Practices in defending Computer systems

### 1. Defense in depth approach

In Cybersecurity you need to reference to many sources. The main sources are:
- Frameworks -> a set of agreed upon policies, procedures and processes that define how information is managed (ex NIST)
- Best Practices -> procedures and processes that are widely accepted within an industry as being effective
- Vendor documentation -> a mix of requirements and suggestions for the specific security configuration of the product (ex Microsoft Server Security Guide)
- Regulatory Requirements -> laws that you must comply with

Defense in Depth is a concept that come from military terminology. It means to put many obstocles in front of the enemy and this way of thinking permits to minimize risks. 
So for Cybersecurity **Defense in Depth** means creating several components to protect my organization. The main components are prevention, detection and response. 
(useful link: http://iieng.org/images/proceedings_pdf/8285E0914047.pdf)

The reference's framework in Cybersecurity is [NIST](https://csrc.nist.gov/publications/sp800). NIST is the National Institute of Standards and Technology. NISTs standards are a guide to help you to set up the various components of your security program. There are many NISTs standards to apply in cyber. Below some important standrds to remember:
- [NIST 800-41r1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf) -> it includes info about firewall types and technologies. It  provides network design examples and recommendations via high level network layouts. 
- [NIST 800-123](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf) -> it contains valuable info about server vulnerabilities and threats
- [NIST 800-175Br1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf) -> It is useful if your organization wants to implement encryption
- NIST CSF -> it provides info on authentication and identity management strategies, risk assessments, managing security in the supply chain and vulnerability disclosure.  

### 2. Principle of least privilage

Principle of least privilage stand for granting the lowest level of access that is required to accomplish task and removing unneccessary access when possible. It applies to people in accesing data, devices, network traffic both external and internal, database and applications.

## System security: securing networks

### 1. Firewall

**Firewall** is the first line of defense. It is a network device that monitors incoming and outcoming traffic. A firewall doesn't know if a traffic is good or bad, it only does what you tell it to do. The main kind of firewalls are:
- Network firewall -> it is a device that separates your local network to the outsides. It has components (CPU, RAM, long-term storage)
- Host based firewall -> it is a host based firewall typically runs within an OS on a computer (wx Windows Firewall or MAC OS Firewall). It protects only the computer and the    services is running on. 
- Application firewall  -> it protects applications

Today we also have Next Gen Firewall that permits capabilities beyond a traditional, statful firewall. In fact it permits not only to monitor the incoming and outcoming traffic but also to add some features like application awareness and control, integrated intrusion prevention and cloud-delivered threat intelligence. 

A baisc Cisco firewall rule consists:
- The interface the traffic is travesing
- The action being taken (e.g. permit or deny)
- The protocol being used
- The objects involved e.g. host or object groups
- The service or port involved (https, port 20)

Example: if we had a vendor with an IP of 22.11.33.44 that wanted to access our database server with an IP of 10.10.10.19 on port 9081 on firewall interface Acme-Ingress here is what the rule might look like:

**access-list Acme-Ingress extended permit tcp host 22.11.33.44 host 10.10.10.19 eq 9081**

Components:
**Acme-Ingress** -> the name of the internal interface
**extended permit** -> flexibility in matching traffic and the ability to match based on protocol, source and destination address. 
**TCP** -> protocol used
**22.11.33.44** -> vendor host
**10.10.10.19** -> destination of the db server
**eq 9081** -> the port used

### 2. Wireless
Choosing the right vendor is key when developing your wireless solution. It si important to tak in consideration some keys like the locarions and the number of employes and how this aspects could change in the future. It is also important if it is based on cloud or on prem solution.  

Another important step is the authentication method and encryption method to choose. Below some methods:
- EAP(extensible authentication protocol with radius) -> allows open authentiction to the client, usually with radius server
- PEAP(protected extensible authentication protocol) -> similar to EAP but adds RLS tunnerl
- WPA2 Enterprise -> 802.1x encryption

Some security measures to protect your wireless:
- use lower power on access points
- use WIDS/WIPS: **wireless intrusion detection/prevention system**
- guest access routes with zerp visibility of business network

### 3. [IDS\IPS](https://www.dnsstuff.com/ids-vs-ips)

**IDS** means intrusion detection system, it can be a hardware or a vm. It is a passive tool that monitors and reports. So it is up to the security analyst to take action. An **IPS** is an active tool and it takes actions.  

**IDS Rule**

alert tcp any any -> 131.131.129.1 111 (msg:"RPC Attempt";sid:1000001;)

- alert -> notify us when the rule fires, it will send an alert to the administrator
- any -> the source **any** indicates any source port will fire the alert
- 131.131.129.1 -> it is a destination IP Address (our address)
- 111 -> destination port
- msg:"RPC Attempt";sid:1000001; -> it is the rule options and it includes the message and the sid number that the admin will receive

### 4. Securing Windows at the OS Level

**Windows services** are small programs that run in  the background of the Operating System. Windows services are generally single-task that perform only one action. Disabling services that are no longer needed reduces the attack surface of the machine. 
There are three primary types of windows services accounts:

- Local service account -> the worker process doesn't require access outside of the server in which it is runnning
- Network Service account -> it has fewer access privileges on the system than the local system user account
- Local system account -> it is a predefined local account used by service control manager

To access windows services, you can easily type **windows key + R then type "Services.msc"**

To **set or control windows file permissions** we have to follow these steps:
- Right click on the properrties and select the security tab
- Select edit 
- Remove or addpermissions

To know the version of your windows, you can simply digit winver in the command line. When performing a security analysis, trubleshooting performance issues or performing incident response os when istalling an application it is important to know the version installed in the machine. Go to powershell and digit **Get-HotFix** to know the last update installed. 
There are many kind of updates on Microsoft:
- Critical update -> it is a widely released fix for a specific problem that addresses a critical non security-related bug
- Definition update -> it is a widely released and frequent software update that contains additions to product's definition database
**Definitio database are used to detect objects that have specific attributes, such as malicious code, phising websites or junk mail.** 
- Driver -> a driver is the software that interacts between your operating system and the device or hardware
- Feature pack -> it is distributed outside the context of a product release 
- Security update -> it is a widely released fix for a specific product, security-related vulnerability
- Security pack -> it is tested cumulative set of all hotfixes, security updates, critical updates and updates 
- Tool -> it is a utility of feature that helps complete a task or set of tasks
- Update -> it addresses a non-critical, non security-related bug

Beginning in 2016, Microsoft views the Windows Operating System as a service that means updates must be installed automatically to have the optimal experience. IT department usually run some centralized windows patch management. 
- WSUS (Windows Server Updates Services) -> it is a free utility to help centralize update management, automate the installation of updates at a time that most benefits the organization and manage the bandwidth consumption of updates
- SCCM (System Center Configuration Manager) -> it is a product developed by Microsoft that can be used for windows updates, installation of new applications, OS upgrades and ativirus scan. In other words, it permits to manage a large number of computers running on windows.

## Monitoring and logging for detection of malicious activity

### 1. System event logs

Logs are records of events that take place on the computer. They help you track and troubleshoot problems. The windows event logs contains logs from OS and aplications. Windows system event logs are messages generated by the windows OS. 3 primary categories of event logs in Windows:

- System -> the system event log is for general system events, Services starting and stoping and so on
- Security -> Security event log is for login attempts and permissions events
- Applictaion -> The application log is for events associated specifically with applications. Think Office or Adobe. 

From the categoies saw before we could have 5 kinds of events:

- Error -> an error is a representation of real problem with the system. A hung service or a disk that is falling
- Warning -> a warning is an event that indicates a pending problem, low disk space for example
- Information -> this is the most common event, it is simply logs that an event took place successfully
- Success Audit -> a succes audit is when an audited event was successful. Such as you typed your psw in correctly to login
- Failure Audit -> a failure audit is when an audited event was unsuccesful. When you attempt to access a folder without permissions for example.

Steps to check for failed login attempts:
- Open powershell
- Run **GET-EVENTLOG -Logname Security -InstanceId 4625 -Newest 25** where we are requiring to get info from the Security where the instance ID of the failed login is 4625
- For a deeper analysis Run event viewer 
- Go to **Windows Logs** 
- Click on **Security**
- Scroll the bar and check the failur vent with ID 4625

### 2. Monitoring Network Traffic
You should monitor traffic for several reasons:
- **Firewall** logs for indications of an attack or breach
- [**Performance**](https://techcommunity.microsoft.com/t5/ask-the-performance-team/windows-performance-monitor-overview/ba-p/375481) logs to catch problems before they cause an outage
- **Scalability** to know when to add capacity
- **Compliance** all compliance regulations require some form of monitoring

Below the main items to monitor:
- Firewalls -> you should always monitor your firewall logs
- Public Facing Servers -> all traffic to and from as well as any application logs
- Wireless -> you should monitor failed connection attempts on your wireless infrastructure
- Sensitive Data/Intellectual Property -> anywhere there is a sensitive information such as PII or intellectual property should be monitored

Some methods for retrieving logs from networked devices:
- Netflow/SFlow -> it is a Cisco proprietary tool and SFlow is its open source conterpart. They primarily collect data from networking devices and gather information such as IPs, Ports, and protocols involved
- SNMP -> it is Simple Network Management Potocol and it performs similary to Netflow
- Wireshark -> it is an open source tool used to analyze packet captures.
- Netstat -> it is a built-in command-line networkutility in Windows/Mac/Linux that shows active connections to your machine. Excellent for troubleshooting
- Perform -> it is a windows utility for the analysis of windows performance

Reviewing reports generated by your security appliances/servers is a primary responsability for analysts. Firewalls and IDS provide a wealth of information on malicious actors attempting to compromise your environment.

It is important to perform the following steps when triaging an alert report:
- **Resarch** reach out to the owner of the internal IP address and ask them if they recognize the trafic. This will help to eleiminatea config issue
- **Report** if the traffic is not expected, report it to the abuse contact in the Whols information
- **Block** if the traffic is from a malicious sender you can manualy add it to your blocklist
- **Updates** ensure that any system that is being probed for a vulnerability is fully patched

**Key Terms**

**PII**: Personally identifiable information, is any data that could potentially be used to identify a particular person. Examples include a full name, Social Security number, driver's license number, bank account number, passport number, and email address.

**WhoIs**: WHOIS isn't an acronym, though it may look like one. In fact, it is the system that asks the question, who is responsible for a domain name or an IP address? In other words, it's the contact information for IP addresses and Websites.

**Netstat command on PoweShell**
- netstat -at :  view the current connections on the OS
- netstat -r : to view the routing table
- netstat -l : to view ports listening to traffic 
- netstat -atep | grep ssh : to view all the current ssh connections

Useful link for cheking virus:
- https://whois.net/
- https://www.virustotal.com/gui/home/upload
- https://www.abuseipdb.com/

### 3. [SIEM](https://www.gartner.com/reviews/market/security-information-event-management)

**SIEM** stands for **Security Information and Event Management**, it is an application that serves as a log aggregator and more importantly, analyzes the logs to allow alerting, dashboard creation and efficient queries to run. 

**SIEMs** allow you to retain your log data for much longer. In particular, networking equipment don't typically have much storage and logs are overwritten frequently. Some considerations when you choose your SIEM solution:
- **Licensing** -> knowing what is the licensing model and if it is based on users, nodes or volume of events
- **Scalability** -> knowing if your organization experience rapid growth, he solution will be able to keep it up
- **Dashboards** -> difficulty in costumize existing and make new dashboards
- **Alerts** -> knowing if the solution is capable of real-time alerting
- **Query language** -> knowing how much complicated is the query language and if there are documnetation available
 
 Types of SIEMs:
 
 - [**Open Source SIEM**](https://www.dnsstuff.com/free-siem-tools)
 - [**Commericial SIEM**](https://logz.io/blog/top-5-commercial-siem-tools/)
 
 ## Cryptography Basics
 
 ### 1.Introduction to Encryption
 In cryptography, encryption is the process of taking data that is plaintext (readable data) and converting it via a mathematical algorithm into ciphertext. Only the authorized parties with the appropriate key can reverse the process and view the data. 
 
The first type of encryption is the **Symmetric encryption**: it uses only one key, a secret ket to both encrypt and decrypt the data. The key can be in the form of a passcode or a series of randomized letters and numbers from a generator or RNG. There are two types of symetric encryption algorithms:
- **Block algorithms** -> in which set length bits are encrypted with the use of a specific secret key. As the data is being encrypted the system holds the data in memory as it waits for the block to complete
- **Stream algorithms** -> the data is encrypted as it strems and is not retained in system memory. 

The types of symmetric encryption are:
- **AES**: advanced encryption standard was designed around the start of this century to replace DES. 
- **Twofish**
- **RC4** Rivest Cipher 4

Symmetric Strengths and Weknesses:
- Very fast
- Each party already has the key so the data can be transmitted in any manner
- Key transport is difficult. The only true secure way is to hand it from person to person
- Once key is exchanged there is no identity verification as to who has the key

The second type is **asymmetric encryption** in which keys are in pairs. It is known as a public key cryptography because one of the keys is usually public and  the other secret. So one encrypts and the other decrypts. To work successfully, asymmetric relies on a key management system in the form of a public key infrastructure. A public key infrastructures (PKI) is a set of servers, software and protocols that manage the keys of a group of users. PKI uses digital certificate to verify identity.
Below some types of asymmetric encryption:
- RSA -> Riverst Shamir Adleman is used primerly for computer messaging. RSAs keys are created by generating two large prime numbers and perform additional mathematical formulations on them, creating the public key. Then the public key is sent to anyone that requests it. They encrypt the data and send it back to the recipient. After that the primary key is used in conjuction with one of the original prime numbers to decrypt the data.
- Diffie-Hellman -> 


 
 
 
 
 
 ### 2.Encryption in Transit
 
 
 
 
 
 
 
 ### 3.File Hashes and Digital Signatures
 

















