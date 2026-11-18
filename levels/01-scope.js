export default {
  id: "01-scope",
  order: 1,
  tier: "beginner",
  title: "Stay in scope",
  term: "Scope and rules of engagement",
  card: {
    what: "Scope sets the boundaries of a test: which systems may be tested and what types of testing are expected. The rules of engagement (ROE) are the detailed guidelines and constraints for carrying out the testing, and they authorise the testers to do the activities they define. NIST SP 800-115 says an assessment plan should list the systems that are authorised and, separately, specific systems that are not.",
    why: "Under section 1 of the Computer Misuse Act 1990, it is an offence to cause a computer to perform a function with intent to secure access to a program or data when that access is unauthorised and you know it is. Broadly, access is unauthorised if you are not entitled to control access of that kind and nobody who is entitled has consented to you having access of that kind (section 17(5), which is subject to section 10). Never test a real system without authorisation.",
    example: "You are given 192.0.2.10 and 192.0.2.11 in writing, and told 198.51.100.7 is excluded. Scanning the excluded host would go beyond what you were authorised to do.",
  },
  world: {
    hosts: [
      {
        ip: "192.0.2.10",
        hostname: "web01.example.test",
        inScope: true,
        services: [
          { port: 22, proto: "tcp", state: "open", service: "ssh", version: "" },
          { port: 80, proto: "tcp", state: "open", service: "http", version: "" },
        ],
      },
      {
        ip: "192.0.2.11",
        hostname: "files01.example.test",
        inScope: true,
        services: [
          { port: 22, proto: "tcp", state: "open", service: "ssh", version: "" },
          { port: 443, proto: "tcp", state: "open", service: "https", version: "" },
        ],
      },
      {
        ip: "198.51.100.7",
        hostname: "pay.example.test",
        inScope: false,
        services: [{ port: 443, proto: "tcp", state: "open", service: "https", version: "" }],
      },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional client, fictional hosts).\nStart with the written authorisation in engagement/scope.txt.\nThe only tool installed for this task is nmap. Type help for the built-in commands.",
      "/home/analyst/engagement/scope.txt":
        "ENGAGEMENT AUTHORISATION (fictional exercise document)\n\nClient:    Example Retail Ltd (fictional)\nTester:    A. Analyst\nSigned:    client IT director (fictional)\n\nAUTHORISED TARGETS\n  192.0.2.10    web01.example.test\n  192.0.2.11    files01.example.test\n\nEXCLUSION LIST (not authorised)\n  198.51.100.7  pay.example.test\n                run by a third-party payment provider, which has not consented\n\nPERMITTED TESTING\n  Port and service identification with nmap, authorised targets only.\n\nNOT PERMITTED\n  Any activity against a host that is not listed under AUTHORISED TARGETS.\n\nPOINT OF CONTACT\n  security@example.test - ask before doing anything this document does not cover.",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^nmap (192\\.0\\.2\\.10|web01\\.example\\.test)$",
      output:
        "Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 14:05 +0000\nNmap scan report for web01.example.test (192.0.2.10)\nHost is up (0.0021s latency).\nNot shown: 998 closed tcp ports (conn-refused)\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n\nNmap done: 1 IP address (1 host up) scanned in 0.14 seconds",
      event: "scanned:192.0.2.10",
    },
    {
      match: "^nmap (192\\.0\\.2\\.11|files01\\.example\\.test)$",
      output:
        "Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 14:06 +0000\nNmap scan report for files01.example.test (192.0.2.11)\nHost is up (0.0019s latency).\nNot shown: 998 closed tcp ports (conn-refused)\nPORT    STATE SERVICE\n22/tcp  open  ssh\n443/tcp open  https\n\nNmap done: 1 IP address (1 host up) scanned in 0.12 seconds",
      event: "scanned:192.0.2.11",
    },
  ],
  outOfScope: {
    hosts: ["198.51.100.7", "pay.example.test"],
    message:
      "You targeted a host on the exclusion list in your written authorisation, so you had no permission to test it. It is run by a third party that has not consented. Testing it would first need a change to the written scope, and NIST SP 800-115 notes that the owner of a third-party network usually must also consent in writing. In this exercise the engagement ends here.",
  },
  objectives: [
    {
      id: "read-scope",
      prompt: "Read the written authorisation before you touch anything: cat engagement/scope.txt",
      check: { type: "event", value: "read:/home/analyst/engagement/scope.txt" },
      success: "Good. Testing starts from the written scope, not from what a host looks like.",
    },
    {
      id: "scan-web01",
      prompt: "Scan the first authorised target with nmap (IP address or hostname).",
      check: { type: "event", value: "scanned:192.0.2.10" },
      success: "web01 is in scope. nmap with only a target scans the 1,000 most common TCP ports.",
    },
    {
      id: "scan-files01",
      prompt: "Scan the second authorised target with nmap.",
      check: { type: "event", value: "scanned:192.0.2.11" },
      success: "files01 is in scope too.",
    },
    {
      id: "count-hosts",
      prompt: "Type a number: how many hosts does the document authorise you to test?",
      check: { type: "answer", value: ["2", "two"] },
      success: "Two authorised targets. Everything else, including the excluded host, stays untouched.",
    },
  ],
  defence: {
    prompt:
      "The client asks what the written authorisation should contain before you start. Which answer matches NIST SP 800-115?",
    check: {
      type: "choice",
      value:
        "Which systems and networks are authorised to be tested (for example by IP address), and which specific systems are not",
      options: [
        "Which systems and networks are authorised to be tested (for example by IP address), and which specific systems are not",
        "Only the tester's name and the dates of the test",
        "Only the client's company name",
        "Only the systems that are authorised, because anything not mentioned is allowed",
      ],
    },
    explanation:
      "NIST SP 800-115 section 6.5 says the assessment plan should identify which systems and networks are authorised to be examined and tested, for example by IP addresses or address ranges, and should also list specific systems that are not authorised, at a minimum by IP address. Names and dates alone, or a company name alone, do not answer the plan's basic questions about scope. Leaving exclusions out does not make unlisted systems allowed: under section 17(5) of the Computer Misuse Act 1990 (subject to section 10), access of any kind is unauthorised if you are not entitled to control access of that kind and do not have consent to it from someone who is.",
  },
  quiz: {
    question:
      "Section 1(1) of the Computer Misuse Act 1990: what must the person know at the time they cause the computer to perform the function?",
    options: [
      "That the access they intend to secure is unauthorised",
      "That the data they are after is personal data",
      "That their actions will cause damage",
      "That the computer belongs to a business",
    ],
    answer: 0,
    explanation:
      "Section 1(1)(c) requires that he knows at the time he causes the computer to perform the function that the intended access is unauthorised. The three paragraphs of section 1(1) say nothing about personal data, damage or who owns the computer. Section 1(2) adds that the intent need not be directed at any particular program or data, or at a program or data of any particular kind, or held in any particular computer.",
  },
  glossary: [
    {
      term: "Scope",
      definition:
        "The boundaries of a test: which systems and networks it is authorised to cover and what types of testing are expected. NIST SP 800-115 says the assessment plan should identify which systems and networks are authorised to be examined and tested, and list specific systems that are not.",
    },
    {
      term: "Rules of engagement (ROE)",
      definition:
        "A document that contains the same information as an assessment plan and also addresses testing activities that are usually prohibited by the organisation, such as attacks to compromise systems. NIST SP 800-115 says the ROE provides authorisation for the assessors to carry out such activities.",
    },
    {
      term: "Exclude list",
      definition:
        "The list of systems that are not authorised for testing. NIST SP 800-115 Appendix B calls this the exclude list.",
    },
    {
      term: "Unauthorised access (Computer Misuse Act 1990)",
      definition:
        "Section 1 makes it an offence to cause a computer to perform any function with intent to secure access to any program or data held in any computer, where the access is unauthorised and the person knows it is. Section 17(5) says access is unauthorised if the person is not entitled to control that kind of access and does not have consent from someone who is. On conviction on indictment the maximum under section 1(3)(c) is two years' imprisonment, a fine, or both.",
    },
  ],
  hints: [
    "Start by reading the written authorisation: cat engagement/scope.txt",
    "Scan each authorised target with: nmap <ip-or-hostname>. Do not name anything from the exclusion list.",
    "For the last objective, type the number of authorised targets and press Enter.",
  ],
  solution: [
    "cat engagement/scope.txt",
    "nmap 192.0.2.10",
    "nmap files01.example.test",
    "2",
    "Which systems and networks are authorised to be tested (for example by IP address), and which specific systems are not",
  ],
  sources: [
    {
      claim: "Section 1(1) CMA 1990: offence elements (function with intent to secure access, access unauthorised, knows it is); s.1(2) intent need not be directed at any particular program or data; s.1(3)(c) maximum on indictment two years, a fine or both",
      url: "https://www.legislation.gov.uk/ukpga/1990/18/section/1",
    },
    {
      claim: "Section 17(5) CMA 1990: access is unauthorised if the person is not entitled to control that access and has no consent from someone who is",
      url: "https://www.legislation.gov.uk/ukpga/1990/18/section/17",
    },
    {
      claim: "NIST SP 800-115 section 6.5: the assessment plan identifies authorised systems (IP addresses or ranges) and lists systems not authorised, at minimum by IP address; the owner of a third-party network usually must also consent in writing; scope questions during an assessment go to the organisation's point of contact; ROE contains the same information as an assessment plan and provides authorisation for usually prohibited activities",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
    },
    {
      claim: "NIST SP 800-115 Appendix B: the ROE target section identifies authorised and unauthorised systems and calls the list of systems not authorised the exclude list",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
    },
    {
      claim: "NIST SP 800-115 Appendix F glossary: rules of engagement are detailed guidelines and constraints regarding the execution of information security testing, and give the test team authority to conduct defined activities",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
    },
    {
      claim: "NCSC: the output of scoping is a document stating the technical boundaries of the test and the types of test expected; if testers find components outside scope they may suggest a scope change or record the exclusion as a limitation",
      url: "https://www.ncsc.gov.uk/guidance/penetration-testing",
    },
    {
      claim: "Nmap: the simple command nmap <target> scans 1,000 TCP ports on the host",
      url: "https://nmap.org/book/man-port-scanning-basics.html",
    },
    {
      claim: "Nmap: by default it performs a SYN scan but substitutes a TCP connect scan if the user lacks raw packet privileges (the simulated analyst account is unprivileged)",
      url: "https://nmap.org/book/man-port-scanning-techniques.html",
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
      claim: "Nmap 7.98 source (nmap.cc, output.cc, portreasons.cc, scan_engine_connect.cc, nmap-services): 'Starting Nmap 7.98 ( https://nmap.org ) at <date> <UTC offset>', 'Nmap scan report for name (ip)', 'Host is up (Ns latency).', 'Not shown: N closed tcp ports (conn-refused)' for a connect scan, PORT STATE SERVICE table (22 ssh, 80 http, 443 https), blank line, 'Nmap done: 1 IP address (1 host up) scanned in N seconds'",
      url: "https://nmap.org/dist/nmap-7.98.tar.bz2",
    },
    {
      claim: "Nmap changelog: 7.92 changed the 'Not shown:' lines to give more detail; 7.97 prints the time zone as an offset from UTC",
      url: "https://nmap.org/changelog.html",
    },
  ],
};
