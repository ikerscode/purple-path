export default {
  id: "03-ports",
  order: 3,
  tier: "beginner",
  title: "What is listening?",
  term: "Ports, services and the TCP handshake",
  card: {
    what: "A TCP connection is normally set up with a three-way handshake: one side sends a SYN, the other answers SYN,ACK, and the first replies with an ACK (RFC 9293 section 3.5). Nmap sorts each port it probes into a state, such as open (an application is accepting connections), closed (reachable, but nothing is listening) or filtered (packet filtering stops Nmap from telling whether it is open).",
    why: "The Nmap reference guide notes that security-minded people know each open port is an avenue for attack, and that administrators try to close or protect open ports with firewalls without thwarting legitimate users. Scan only systems you have written permission to test.",
    example: "If a server exists only to serve a website, an open FTP port is an extra service. A version scan can name the software behind it.",
  },
  world: {
    hosts: [
      {
        ip: "192.0.2.30",
        hostname: "web02.example.test",
        inScope: true,
        services: [
          { port: 21, proto: "tcp", state: "open", service: "ftp", version: "vsftpd 3.0.5" },
          { port: 22, proto: "tcp", state: "open", service: "ssh", version: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)" },
          { port: 23, proto: "tcp", state: "filtered", service: "telnet", version: "" },
          { port: 80, proto: "tcp", state: "open", service: "http", version: "nginx 1.18.0 (Ubuntu)" },
        ],
      },
      {
        ip: "192.0.2.31",
        hostname: "db01.example.test",
        inScope: false,
        services: [],
      },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional client, fictional hosts).\nStart with the written authorisation in engagement/scope.txt.\nThe only tool installed for this task is nmap, run as an ordinary user. Type help for the built-in commands.",
      "/home/analyst/engagement/scope.txt":
        "ENGAGEMENT AUTHORISATION (fictional exercise document)\n\nClient:    Example Retail Ltd (fictional)\nTester:    A. Analyst\nSigned:    client IT director (fictional)\n\nAUTHORISED TARGETS\n  192.0.2.30    web02.example.test\n\nEXCLUSION LIST (not authorised)\n  192.0.2.31    db01.example.test\n                database server run by another team, which has not agreed to testing\n\nWHAT THE CLIENT TOLD US ABOUT web02\n  It exists only to serve the public website.\n  Staff update the site over SSH.\n  Nobody is expected to use FTP or Telnet on it.\n\nPERMITTED TESTING\n  Port and service identification with nmap, authorised target only.\n\nNOT PERMITTED\n  Any activity against a host that is not listed under AUTHORISED TARGETS.\n\nPOINT OF CONTACT\n  security@example.test - ask before doing anything this document does not cover.",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^nmap (192\\.0\\.2\\.30|web02\\.example\\.test)$",
      output:
        "Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 14:31 +0000\nNmap scan report for web02.example.test (192.0.2.30)\nHost is up (0.0021s latency).\nNot shown: 996 closed tcp ports (conn-refused)\nPORT   STATE    SERVICE\n21/tcp open     ftp\n22/tcp open     ssh\n23/tcp filtered telnet\n80/tcp open     http\n\nNmap done: 1 IP address (1 host up) scanned in 4.63 seconds",
      event: "scanned:192.0.2.30",
    },
    {
      match: "^nmap (-sV (192\\.0\\.2\\.30|web02\\.example\\.test)|(192\\.0\\.2\\.30|web02\\.example\\.test) -sV)$",
      output:
        "Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 14:33 +0000\nNmap scan report for web02.example.test (192.0.2.30)\nHost is up (0.0020s latency).\nNot shown: 996 closed tcp ports (conn-refused)\nPORT   STATE    SERVICE VERSION\n21/tcp open     ftp     vsftpd 3.0.5\n22/tcp open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)\n23/tcp filtered telnet\n80/tcp open     http    nginx 1.18.0 (Ubuntu)\nService Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 7.91 seconds",
      event: "versioned:192.0.2.30",
    },
  ],
  outOfScope: {
    hosts: ["192.0.2.31", "db01.example.test"],
    message:
      "You targeted a host on the exclusion list in your written authorisation, so you had no permission to test it. It is a database server run by another team that has not agreed to testing. Testing it would first need a change to the written scope. In this exercise the engagement ends here.",
  },
  objectives: [
    {
      id: "read-scope",
      prompt: "Read the written authorisation first: cat engagement/scope.txt",
      check: { type: "event", value: "read:/home/analyst/engagement/scope.txt" },
      success: "Note what the client says web02 is for. That decides which open ports are needed and which are not.",
    },
    {
      id: "scan-default",
      prompt: "Scan the authorised target with nmap (IP address or hostname).",
      check: { type: "event", value: "scanned:192.0.2.30" },
      success: "With only a target, nmap scans the 1,000 most common TCP ports. You run as an ordinary user, and Nmap uses a TCP connect scan when SYN scan is not an option because the user lacks raw packet privileges. The SERVICE column here is looked up by port number, so it only says what is probably there.",
    },
    {
      id: "filtered-port",
      prompt: "Type the number of the port that Nmap lists as filtered.",
      check: { type: "answer", value: ["23", "23/tcp"] },
      success: "Port 23 is filtered. Nmap does not know whether anything is listening there.",
    },
    {
      id: "filtered-meaning",
      prompt: "What does the state filtered mean in Nmap?",
      check: {
        type: "choice",
        value: "Nmap cannot determine whether the port is open, because packet filtering prevents its probes from reaching the port",
        options: [
          "An application is actively accepting connections on the port",
          "The port is reachable, but there is no application listening on it",
          "Nmap cannot determine whether the port is open, because packet filtering prevents its probes from reaching the port",
          "The port is reachable, but Nmap cannot determine whether it is open or closed",
        ],
      },
      success: "Right. The Nmap guide says the filtering could come from a dedicated firewall device, router rules or host-based firewall software, and that such ports give attackers little information.",
    },
    {
      id: "scan-version",
      prompt: "Now ask Nmap to identify the software behind each open port: nmap -sV <target>",
      check: { type: "event", value: "versioned:192.0.2.30" },
      success: "Version detection interrogates the open ports to find the service protocol, application name and version number where it can. The Nmap guide says an accurate version number helps dramatically in determining which exploits a server is vulnerable to.",
    },
    {
      id: "ftp-version",
      prompt: "Type the name and version of the FTP server, as shown in the VERSION column.",
      check: { type: "answer", value: ["vsftpd 3.0.5"] },
      success: "vsftpd 3.0.5 on port 21. The scope document says nobody is expected to use FTP on this server.",
    },
  ],
  defence: {
    prompt:
      "The client's own description says web02 only serves the website and staff use SSH. Which recommendation follows NIST guidance?",
    check: {
      type: "choice",
      value:
        "Remove the FTP service, or disable it if it cannot be removed, and keep the firewall on deny by default so that only needed traffic is permitted",
      options: [
        "Leave FTP running, because each extra service is harmless if nobody is expected to use it",
        "Treat port 23 as safe, because Nmap reported it as filtered rather than open",
        "Remove the FTP service, or disable it if it cannot be removed, and keep the firewall on deny by default so that only needed traffic is permitted",
        "Switch the firewall off so that every port shows up as plainly open or closed",
      ],
    },
    explanation:
      "NIST SP 800-123 section 4.2.1 says to remove services that are not required (and disable any that cannot be removed), lists FTP among the file services that should usually be removed if not required, and says each service added to a host increases the risk of compromise because it is another possible avenue of access. Removing is preferable to disabling because a removed service cannot be re-enabled by an attack on its settings or by mistake. NIST SP 800-41 Revision 1 section 4 says firewalls should generally block traffic that has not been expressly permitted (deny by default), which it calls more secure than permitting everything that is not explicitly forbidden. A filtered state does not show the port is safe: the Nmap guide says it means Nmap cannot determine whether the port is open.",
  },
  quiz: {
    question: "In the TCP three-way handshake in RFC 9293 section 3.5, what does the server send in reply to the client's first segment?",
    options: [
      "A segment with only the ACK flag set",
      "A segment with both the SYN and ACK flags set",
      "A segment with the RST flag set",
      "A segment carrying the first data",
    ],
    answer: 1,
    explanation:
      "In Figure 6 of RFC 9293 the first peer sends a SYN, the second replies with a segment whose control flags are SYN,ACK (it acknowledges the SYN it received), and the first peer then sends an empty ACK. One case where a reset is sent is a TCP in the CLOSED state (no connection exists) responding to an incoming segment that is not itself a reset (section 3.10.7.1).",
  },
  glossary: [
    {
      term: "Three-way handshake",
      definition:
        "The procedure TCP uses to establish a connection (RFC 9293 section 3.5). In the simplest case one peer sends a SYN, the other replies with SYN,ACK, and the first sends an ACK.",
    },
    {
      term: "Port states (open, closed, filtered)",
      definition:
        "Nmap's description of how it sees a port. Open: an application is actively accepting TCP connections, UDP datagrams or SCTP associations. Closed: the port is accessible but no application is listening on it. Filtered: Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching it. Nmap says these states describe how Nmap sees the port, not an intrinsic property of the port.",
    },
    {
      term: "TCP connect scan",
      definition:
        "Nmap's default TCP scan type when SYN scan is not an option, for example when the user lacks raw packet privileges. Nmap asks the operating system to establish a connection with the connect system call, which completes connections to open ports.",
    },
    {
      term: "Version detection (-sV)",
      definition:
        "After ports are discovered, Nmap interrogates them to try to determine the service protocol, application name, version number and other details such as the OS family. Most services do not provide all of this information.",
    },
    {
      term: "Deny by default",
      definition:
        "NIST SP 800-41 Revision 1: firewalls should generally block all inbound and outbound traffic that has not been expressly permitted by the firewall policy, that is, traffic that is not needed by the organisation.",
    },
  ],
  hints: [
    "Start by reading the written authorisation: cat engagement/scope.txt",
    "Scan the authorised target with: nmap <ip-or-hostname>. For software names and versions add -sV. Do not name anything from the exclusion list.",
    "Look at the STATE column for the filtered port, and at the VERSION column for the FTP server.",
  ],
  solution: [
    "cat engagement/scope.txt",
    "nmap 192.0.2.30",
    "23",
    "Nmap cannot determine whether the port is open, because packet filtering prevents its probes from reaching the port",
    "nmap -sV web02.example.test",
    "vsftpd 3.0.5",
    "Remove the FTP service, or disable it if it cannot be removed, and keep the firewall on deny by default so that only needed traffic is permitted",
  ],
  sources: [
    {
      claim: "Nmap: the simple command nmap <target> scans 1,000 TCP ports; Nmap divides ports into six states; states describe how Nmap sees a port rather than intrinsic properties; open means an application is actively accepting TCP connections, UDP datagrams or SCTP associations; security-minded people know each open port is an avenue for attack and administrators try to close or protect them with firewalls without thwarting legitimate users; closed means accessible but no application listening; filtered means Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port, from a firewall device, router rules or host-based firewall software, and these ports provide little information to attackers",
      url: "https://nmap.org/book/man-port-scanning-basics.html",
    },
    {
      claim: "Nmap: TCP connect scan is the default TCP scan type when SYN scan is not an option, which is the case when a user does not have raw packet privileges; it asks the operating system to establish a connection with the connect system call, which completes connections to open target ports",
      url: "https://nmap.org/book/man-port-scanning-techniques.html",
    },
    {
      claim: "Nmap: version detection interrogates discovered ports to determine the service protocol, application name, version number and more (device type, OS family, CPE) where available, though most services do not provide all of this; the nmap-services lookup says ports probably correspond to a service; an accurate version number helps dramatically in determining which exploits a server is vulnerable to; -sV enables version detection",
      url: "https://nmap.org/book/man-version-detection.html",
    },
    {
      claim: "Nmap: by default Nmap scans the most common 1,000 ports for each protocol",
      url: "https://nmap.org/book/man-port-specification.html",
    },
    {
      claim: "Nmap: written authorization from the target network representatives is the best way to avoid controversy before scanning",
      url: "https://nmap.org/book/legal-issues.html",
    },
    {
      claim: "Nmap 7.98 source (output.cc, portlist.cc, portreasons.cc, scan_engine_connect.cc, nmap-service-probes): normal-output layout 'Starting Nmap 7.98 ( https://nmap.org ) at <date> <UTC offset>', 'Nmap scan report for name (ip)', 'Host is up (Ns latency).', 'Not shown: N closed tcp ports (conn-refused)' for a connect scan, PORT STATE SERVICE (VERSION with -sV) table, a 'Service Info:' line built from OS and CPE data matched by -sV, 'Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .', 'Nmap done: 1 IP address (1 host up) scanned in N seconds'; nmap-service-probes lines matching 'vsFTPd', 'OpenSSH ... Ubuntu' banners and 'Server: nginx/<version> (Ubuntu)'",
      url: "https://nmap.org/dist/nmap-7.98.tar.bz2",
    },
    {
      claim: "Nmap changelog: 7.92 changed the 'Not shown:' lines to give more detail; 7.97 prints the time zone as an offset from UTC",
      url: "https://nmap.org/changelog.html",
    },
    {
      claim: "RFC 9293 section 3.5: the three-way handshake is the procedure used to establish a connection; Figure 6 shows SYN, then SYN,ACK, then ACK; section 3.10.7.1: a TCP in the CLOSED state (TCB does not exist) sends a RST in response to an incoming segment that does not contain a RST",
      url: "https://www.rfc-editor.org/rfc/rfc9293",
    },
    {
      claim: "NIST SP 800-123 section 4.2.1: remove all services, applications and network protocols that are not required and disable those that cannot be removed; FTP is listed among file and printer sharing services that should usually be removed if not required; removing is preferable to disabling; each service added increases the risk of compromise as another possible avenue of access",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf",
    },
    {
      claim: "NIST SP 800-41 Revision 1 section 4: firewalls should generally block all inbound and outbound traffic not expressly permitted by the firewall policy (deny by default), which is a more secure approach than permitting all traffic not explicitly forbidden; section 4.1.3: deny by default policies should be used for incoming TCP and UDP traffic",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf",
    },
  ],
};
