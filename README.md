# Project Course

## Description

This project is a Python application that implements **intent-based networking** using a large language model (LLM). It integrates the LLM into the decision-making loop of an Software-Defined Network (SDN) by taking natural-language input from the operator and a snapshot of the current network state to propose and implement relevant changes in the network via the SDN controller. This project focuses on the addition of **ingress and egress filtering** in the SDN. The overall goal is to **simplify and automate network management**, so that humans can interact with the network using natural language, allowing for faster troubleshooting, safer action execution with confirmation, smarter decisions, and improved visibility and control in dynamic SDN environments.



## Key Components

#### **Dynamic Network State Retrieval**
Gathers real-time data about the network from the SDN controller, including MAC tables, port statistics, stop port states, flow tables, host-to-switch mappings, and implemented secuity policy rules. This maintains an up-to-date snapshot view of the network state for monitoring and decision-making. 

#### **LLM-Powered Network Diagnostics**
Uses OpenAI GPT-4o-mini to analyze the current network status and determine changes to security policies. The LLM outputs new proposed network security policies as a JSON object (e.g. allow, deny, whitelist, and SAV actions) that the SDN controller can directly implement in the network.

#### **Intent-Based Inference**
Converts natural-language intents into SDN controller–compatible actions for ingress and egress filtering. 
Translates user input like, “Block outbound HTTPS from h5” into precise OpenFlow matches (CIDRs, protocols, and ports) aligned with the current network state and the desired end-state.

#### **Controller-Side Action Implementation**
Executes LLM-generated actions directly on the controller using OpenFlow 1.3. Security rules are implemented as a three-table pipeline, in which:
- Table 0: Security policies, including ingress and egress rules, and HTTPS whitelists
- Table 1: Source Address Validation for anti-spoofing
- Table 2: Standard L2 forwarding for MAC learning

#### **PCAP traces**
To audit and validate actions as well as debug potential issues, the `PacketManager` enables on-demand packet captures using `tcpdump` at chosen switch interfaces. The captures are saved with metadata as `.pcap`files in the `pcap_traces` folder, which can then be viewed and inspected using Wireshark.



## Features for Ingress & Egress Filtering
- **Inbound Service Blocking / Unblocking** 

    *What?* Ingress rules for TCP, UDP, and ICMP.

    *Why?* Provides fine-grained control over which services are allowed to enter the network. It is an important safeguard against malware attacks. Additionally, it enforces policy compliance and allows for safer diagnostics. 

- **Outbound Service Blokcing / Unblocking** 

    *What?* Egress rules for TCP, UDP, and ICMP.

    *Why?* Provides fine-grained control over which services are allowed to leave the network. It is an important safeguard against malware attacks. Additionally, it enforces policy compliance and allows for safer diagnostics. 

- **Source Address Validation (SAV)** 

    *What?* Prevents IP spoofing by binding (IP, MAC, port). 

    *Why?* Prevents IP/MAC spoofing attacks inside the network, as it ensures that hosts are not able to impersonate others. 

- **Whitelisting HTTPS destinations** 

    *What?* All HTTPS is denied in the network by default. User can sleectively whitelist HTTPS destinations. 

    *Why?* HTTPS traffic is encrypted and can hide or disguise malicious traffic in the network. Therefore, enforcing a zero-trust policy for encrypted traffic improves security, as it only allows whitelisted (approved) hosts to be accessed, reducing the attack surface.



## How Does It Work?
- **Network state retrieval:** When the user has requested action, the current state of the network is retrieved for analysis. A JSON object containing the switches, MAC tables, port statistics, port descriptions, stp port states, flow tables, host-to-switch mappings, and existing security policies is retrieved and sent to the LLM for analysis in the first query.
- **Network topology retrieval:** Similarly to the network state data, the network topology, consisting of a static JSON file, is retreived, parsed, and also sent to the LLM along with the first query as contextual information.
- **Recommendation and decision-making:** The user intent, network state and topology data, and the general rules of SDN controller operations are combined to query for a formal diagnosis and recommendation for actionable steps to take to confirm or solve the problem.
- **Format validation:** A second query to the LLM is performed in order to ensure that the actionable output (a list of JSON objects) provided by the first query is precise and in the correct format. This is done to increase the consistency of the final LLM output and make sure that it can be understood and implemented by the SDN controller. It is an important step of the process as general-purpose LLMs, such as ChatGPT and Claude Sonnet, lack the specific fine-tuning for network management and may thus produce varying output, particularly when query prompts are large and contain larger quantities of necessary contextual data.
- **Action implementation:**  If actionable steps are suggested, the network engineer can review the recommendation and allow or deny the actions. If the actions are denied, the agent will return to wait for a new user input. If the user accepts the actions, they will be implemented in the SDN controller directly. 
- **Logging:** 
    - **Network state:** The network state snapshots are stored in the logs/ folder by timestamp.json for future monitoring and improvement. 
    - **Packet captures:** Representative traffic is recorded as packet capture files (.pcap/.pcapng) under logs/ (e.g., logs/<timestamp>.pcap). These captures serve as a packet-level audit trail to validate effects of policies, support troubleshooting, and guide new ingress/egress rules. Captures can be opened in Wireshark or inspected via tshark/tcpdump using display filters (e.g., tcp.port==443, dns, ip.addr==10.0.0.5). File rotation is configured to limit disk usage, and summaries/exports (CSV/JSON) can be generated for reporting.



## Requirements, Installation & Running the App

### Requirements
The application requires **Mininet** and runs on **Python3** (Python 3.8.0 was used in development) 
Required libraries include: 
- openai v.1.97.1
- python-dotenv v.1.0.1
- requests v.2.32.4
- ryu v.4.34
- mininet v.2.3.0.dev6

The Python library requirements are also available in the `requirements.txt` file in the repository root folder. 


### Installation
1. Clone the repository in your local machine as follows: 
`git clone https://github.com/wannalina/project-course.git`
2. Install the dependencies: 
`pip install -r requirements.txt`
3. Ensure that Mininet is up and running


### Running the App

1. **Start**
Move yourself to a separated environment, like comnetsemu.

2. **Mininet and topology initialization:** 
Use the following command: 
`sudo python3 mininet/topology.py`
This will initialize the Mininet network simulation, start the RYU controller, and build the static topology consisting of four switches and six hosts, with the links formed as follows: 
<img src="img/network_topo.png" alt="Network Topology" width="200"/>
Once the controller has finished initializing, test it using the `pingall` command to verify that all hosts can reach each other.

3. **Initialize the main application**
Use the following command to initialize the program: 
`sudo python3 northbound_agent.py`

4. **Ask questions and perform actions**
Observe that the command line interface of `northbound_agent.py`, the program asks for user input (intent) as follows: 
![alt text](img/main_menu.png)
Below is a walk-through of each option and its expected output.

    **Option 1: Start / stop packet captures:**
    After selecting option 1, a new menu opens up as follows: 
    ![alt text](img/pcap_menu.png)
    To start a packet capture at a specific interface of a switch, you must type, "Start packet capture at s1-eth1", for instance. This will begin capturing packets at interface eth1 of switch 1 until it is manually stopped by selecting option 1 again in the main menu and selecting the option "Stop packet capture at {capture ID}" or "Stop all packet captures". Keep in mind that when starting a packet capture, you will receive the capture ID on the command line after the capture starts successfully. This will be needed when stopping a single packet capture as there may be several packet captures at different switches / interfaces active at once, so it is a good idea to write it down.

    **Option 2: Perform an action:**
    After selecting option 2, the program will prompt the user to enter an action to implement in the controller. As this project focuses on ingress and egress filtering, example actions to implement could include the following:
    - **Block / unblock inbound services:** "Allow inbound ICMP for 10.0.0.5/24 and drop other inbound traffic."
    - **Block / unblock outbound services:** Block outbound UDP from 10.0.0.4/24."
    - **Implement Source Address Validation (SAV) as an anti-spoofing measure:** "Enable anti-spoofing so that each access port only accepts IPv4 packets whose source MAC and source IP match the learned host on that port."
    - **Whitelist HTTPS destinations:** "Whitelist outbound HTTPS to h5."

    **Option 0: Exit program**

5. **To test the action**, the user may perform a series of tests in the Mininet terminal window. However, the specific tests depend on the action implemented, so here are a couple of examples: 

    5.1. **To test a blocked inbound service:**
    First, open an xterm window for h5. in the h5 xterm window, type the command `python3 -m http.server 80 &` to set up a listener on the server.
    Then, open an xterm window for any of the other hosts, for example h2. In the xterm window of h2, execute the command `curl -m 3 -v http://10.0.0.5:80/`. The result should 


    5.2. **To test a blocked outbound service:**

    5.3 **To test spoofing attacks:** 

    5.4 **To test whitelisted HTTPS destinations:**


6. **To exit the program**, stop the application by typing "exit" on the `northbound_agent.py` command line interface. Then stop the Mininet instance using the following command: 
`exit`
Finally, clear and clean up any leftover Mininet network states and processes using the command: 
`sudo mn -c`



## LLM Integration Specifics

### Choosing the model
For this project, we integrated the OpenAI GPT-4o-mini family via the OpenAI Python SDK. During development, we compared several general-purpose models (e.g., GPT-4o, GPT-4 Turbo variants, GPT-3.5) to balance structured output reliability, prompt complexity, latency, token limits, and cost.
GPT-4o-mini was selected as the default because it consistently produced well-formed JSON (crucial for SDN controller compatibility), delivered fast responses suitable for interactive operations, and provided a strong cost/performance trade-off for iterative, human-in-the-loop workflows.


### Building the prompt



## FAQ

