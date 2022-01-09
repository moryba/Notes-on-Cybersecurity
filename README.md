# Notes on Cybersecurity

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




## Monitoring and logging for detection of malicious activity














