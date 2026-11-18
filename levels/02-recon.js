export default {
  id: "02-recon",
  order: 2,
  tier: "beginner",
  title: "Look before you touch",
  term: "Reconnaissance (passive vs active, OSINT)",
  card: {
    what: "Reconnaissance is gathering information that can be used to support targeting, such as details of the organisation, its infrastructure or its staff. In MITRE ATT&CK, active scanning (T1595) means the adversary probes the victim's infrastructure via network traffic, as opposed to forms of reconnaissance that do not involve direct interaction, such as using search engines or searching open technical databases.",
    why: "OSINT (open-source intelligence) is intelligence produced by collecting and analysing publicly available information to answer a specific question. ATT&CK notes that sites with hiring or business details, and public DNS records such as MX and TXT, can reveal facts about a victim that help targeting.",
    example: "A mail exchanger record that names an outside mail provider is a detail a tester can note without scanning anything.",
  },
  world: {
    hosts: [
      { ip: "203.0.113.10", hostname: "www.northwind.example", inScope: false, services: [] },
      { ip: "203.0.113.20", hostname: "vpn.northwind.example", inScope: false, services: [] },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional client, fictional domain).\nThis phase is open-source collection only: read engagement/scope.txt.\nTools: cat, ls and dig. dig is modelled with +short only, for example: dig +short NS northwind.example",
      "/home/analyst/engagement/scope.txt":
        "ENGAGEMENT AUTHORISATION - PHASE 1 (fictional exercise document)\n\nClient:    Northwind Example Ltd (fictional)\nDomain:    northwind.example\n\nPERMITTED IN PHASE 1\n  Reading public web pages and search results about the client.\n  Public DNS lookups for northwind.example.\n\nNOT PERMITTED IN PHASE 1\n  Sending scans or any other probe traffic to client systems,\n  for example 203.0.113.10 and 203.0.113.20.\n  Active testing needs a separate sign-off from the client.",
      "/home/analyst/osint/careers.txt":
        "NORTHWIND EXAMPLE LTD - CAREERS (public web page, fictional)\n\nIT Support Analyst\nYou will look after staff laptops and help run our public website.\nRemote staff sign in through our VPN portal and use our hosted email.\nApply to: recruitment@northwind.example",
      "/home/analyst/osint/search-results.txt":
        "Search results for \"northwind.example\" (fictional)\n\n1. Northwind Example Ltd - Home\n   www.northwind.example\n2. Staff sign-in - Northwind Example Ltd\n   vpn.northwind.example\n3. Careers at Northwind Example Ltd\n   www.northwind.example/careers",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^dig(?=.* \\+short)(?=.* ns( |$))(?=.* northwind\\.example\\.?( |$)).*$",
      output: "ns1.northwind.example.\nns2.northwind.example.",
      event: "dns:ns",
    },
    {
      match: "^dig(?=.* \\+short)(?=.* mx( |$))(?=.* northwind\\.example\\.?( |$)).*$",
      output: "10 mx1.mail-provider.example.\n20 mx2.mail-provider.example.",
      event: "dns:mx",
    },
    {
      match: "^dig(?=.* \\+short)(?=.* txt( |$))(?=.* northwind\\.example\\.?( |$)).*$",
      output: "\"v=spf1 include:_spf.mail-provider.example -all\"",
      event: "dns:txt",
    },
    {
      match: "^dig(?=.* \\+short)(?=.* www\\.northwind\\.example\\.?( |$))(?!.* (ns|mx|txt|aaaa|cname|soa|any|axfr|ixfr(=[0-9]+)?)( |$)).*$",
      output: "203.0.113.10",
      event: "dns:a:www",
    },
    {
      match: "^dig(?=.* \\+short)(?=.* vpn\\.northwind\\.example\\.?( |$))(?!.* (ns|mx|txt|aaaa|cname|soa|any|axfr|ixfr(=[0-9]+)?)( |$)).*$",
      output: "203.0.113.20",
      event: "dns:a:vpn",
    },
    {
      match: "^dig(?=.* \\+short)(?=.* northwind\\.example\\.?( |$))(?!.* (ns|mx|txt|aaaa|cname|soa|any|axfr|ixfr(=[0-9]+)?)( |$)).*$",
      output: "203.0.113.10",
    },
    {
      match: "^dig(?=.* \\+short)(?=.* ([a-z0-9-]+\\.)*northwind\\.example\\.?( |$))(?!.* (soa|any|axfr|ixfr(=[0-9]+)?)( |$)).*$",
      output: "",
    },
  ],
  outOfScope: {
    hosts: ["203.0.113.10", "203.0.113.20"],
    message:
      "That command named a client system that phase 1 of your written authorisation lists as not permitted. Phase 1 covers open-source collection and public DNS lookups only, and sending scans or any other probe traffic to client systems needs a separate sign-off. In this exercise the engagement ends as soon as a not-permitted address is named.",
  },
  objectives: [
    {
      id: "read-careers",
      prompt: "Read the client's public job advert: cat osint/careers.txt",
      check: { type: "event", value: "read:/home/analyst/osint/careers.txt" },
      success: "Public pages can say how a company works. Note what the advert mentions.",
    },
    {
      id: "read-search",
      prompt: "Read the saved search results about the client: cat osint/search-results.txt",
      check: { type: "event", value: "read:/home/analyst/osint/search-results.txt" },
      success: "Search results are another open source. They name a host you may want to look up in DNS.",
    },
    {
      id: "dns-ns",
      prompt: "Look up the domain's name servers: dig +short NS northwind.example",
      check: { type: "event", value: "dns:ns" },
      success: "NS records name the hosts that should be authoritative for the domain.",
    },
    {
      id: "dns-mx",
      prompt: "Look up where the domain's email is handled: dig +short MX northwind.example",
      check: { type: "event", value: "dns:mx" },
      success: "MX records name the hosts willing to act as mail exchangers; lower preference values are preferred.",
    },
    {
      id: "mail-provider",
      prompt: "Type the domain of the outside mail provider in the MX answers (the part after the mx1. or mx2. label).",
      check: { type: "answer", value: ["mail-provider.example", "mail-provider.example."] },
      success: "ATT&CK notes that DNS MX and TXT records may reveal the use of third-party cloud and SaaS providers.",
    },
    {
      id: "classify-active",
      prompt: "Which of these is active reconnaissance in the ATT&CK sense?",
      check: {
        type: "choice",
        value: "Sending port-scan packets to the company's web server",
        options: [
          "Reading the company's public job adverts",
          "Searching a search engine for the company's name",
          "Sending port-scan packets to the company's web server",
          "Searching an open database of domain registrations",
        ],
      },
      success: "Right: active scans probe victim infrastructure via network traffic. The others use publicly available sources.",
    },
  ],
  defence: {
    prompt:
      "Your report must recommend how the client can reduce what outsiders learn. Which recommendation follows ATT&CK's mitigation guidance for these techniques?",
    check: {
      type: "choice",
      value: "Minimise the amount and sensitivity of data available to external parties",
      options: [
        "Minimise the amount and sensitivity of data available to external parties",
        "Rely on a firewall rule to stop outsiders reading public web pages and DNS records",
        "Publish staff names, roles and contact details on the website",
        "Do nothing, because public information cannot be used for targeting",
      ],
    },
    explanation:
      "For searches of victim-owned websites and open technical databases, ATT&CK says the technique cannot be easily mitigated with preventive controls because it is based on behaviours outside the scope of enterprise defences, and that efforts should focus on minimising the amount and sensitivity of data available to external parties. ATT&CK lists names, roles and contact information on victim-owned websites among the details that can be used for targeting, and describes reconnaissance as gathering information that can support targeting. For DNS specifically, ATT&CK suggests zone transfer policies that enforce a list of validated servers permitted for zone transfers.",
  },
  quiz: {
    question: "In MITRE ATT&CK, what makes a scan \"active scanning\"?",
    options: [
      "The adversary probes victim infrastructure via network traffic",
      "The adversary searches freely available websites for information about the victim",
      "The adversary reads domain registration records in an open database",
      "The adversary reads a news article about the victim",
    ],
    answer: 0,
    explanation:
      "ATT&CK T1595 says active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction. Searching open websites and searching open technical databases, such as registrations of domains and certificates, are separate ATT&CK techniques.",
  },
  glossary: [
    {
      term: "Reconnaissance",
      definition:
        "In MITRE ATT&CK, techniques that involve adversaries actively or passively gathering information that can be used to support targeting. The information may include details of the victim organisation, infrastructure, or staff.",
    },
    {
      term: "Active scanning",
      definition:
        "MITRE ATT&CK T1595: scans where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.",
    },
    {
      term: "OSINT (open-source intelligence)",
      definition:
        "Intelligence produced by collecting, evaluating and analysing publicly available information to answer a specific intelligence question (SANS). SANS also uses \"passive\" for collecting public information without engaging the target and \"active\" for engaging with a target in some fashion, such as messaging them. That is a different meaning of \"active\" from ATT&CK's Active Scanning, which is about probing infrastructure.",
    },
    {
      term: "NS, MX and TXT records",
      definition:
        "DNS record types. RFC 1035: an NS record names a host that should be authoritative for a domain; an MX record has a preference value, where lower values are preferred, and an exchange host willing to act as a mail exchange; a TXT record holds descriptive text. RFC 7208 says SPF records are published as DNS TXT records. ATT&CK notes that DNS MX, TXT and SPF records may reveal the use of third-party cloud and SaaS providers.",
    },
    {
      term: "DNS zone transfer (AXFR)",
      definition:
        "ATT&CK notes that adversaries may use a DNS zone transfer (query type AXFR) to collect all records from a misconfigured DNS server, and suggests zone transfer policies that enforce a list of validated servers permitted for zone transfers.",
    },
  ],
  hints: [
    "Start with the written authorisation: cat engagement/scope.txt. Phase 1 allows open-source collection and public DNS lookups only.",
    "Read the two files in osint/, then use dig with +short, for example: dig +short MX northwind.example",
    "Do not send anything to the IP addresses listed as not permitted. A DNS answer that shows an address is information, not an invitation to scan it.",
  ],
  solution: [
    "cat osint/careers.txt",
    "cat osint/search-results.txt",
    "dig +short NS northwind.example",
    "dig +short MX northwind.example",
    "mail-provider.example",
    "Sending port-scan packets to the company's web server",
    "Minimise the amount and sensitivity of data available to external parties",
  ],
  sources: [
    {
      claim: "Reconnaissance (TA0043) consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting, including details of the victim organisation, infrastructure, or staff",
      url: "https://attack.mitre.org/tactics/TA0043/",
    },
    {
      claim: "Active Scanning (T1595): active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction",
      url: "https://attack.mitre.org/techniques/T1595/",
    },
    {
      claim: "Search Open Websites/Domains (T1593): freely available websites, including social media, news sites and sites hosting business information such as hiring, may hold information about victims that can be used during targeting",
      url: "https://attack.mitre.org/techniques/T1593/",
    },
    {
      claim: "Search Victim-Owned Websites (T1594): victim-owned sites may hold names of departments, locations and key employees' names, roles and contact info; mitigation M1056 says it cannot be easily mitigated with preventive controls and efforts should focus on minimising the amount and sensitivity of data available to external parties",
      url: "https://attack.mitre.org/techniques/T1594/",
    },
    {
      claim: "Search Open Technical Databases (T1596): databases and repositories such as registrations of domains/certificates and public collections of network data may hold information about victims; same M1056 mitigation text",
      url: "https://attack.mitre.org/techniques/T1596/",
    },
    {
      claim: "Gather Victim Network Information: DNS (T1590.002): DNS information includes name servers and records for subdomains and mail servers; MX, TXT and SPF records may reveal third-party cloud and SaaS providers; adversaries may use DNS zone transfer (AXFR) against a misconfigured server; mitigation M1054 suggests zone transfer policies with a list of validated servers",
      url: "https://attack.mitre.org/techniques/T1590/002/",
    },
    {
      claim: "Search Engines (T1593.002): adversaries may use search engines to collect information about victims that can be used during targeting; mitigation M1056",
      url: "https://attack.mitre.org/techniques/T1593/002/",
    },
    {
      claim: "OSINT is intelligence produced by collecting, evaluating and analysing publicly available information to answer a specific intelligence question; passive collection means not engaging the target, active means engaging with them in some fashion such as messaging",
      url: "https://www.sans.org/blog/what-is-open-source-intelligence",
    },
    {
      claim: "P.L. 109-163 s.931(a)(1): OSINT is intelligence produced from publicly available information and collected, exploited and disseminated in a timely manner to an appropriate audience for the purpose of addressing a specific intelligence requirement",
      url: "https://www.govinfo.gov/content/pkg/PLAW-109publ163/html/PLAW-109publ163.htm",
    },
    {
      claim: "RFC 1035: NS record names a host that should be authoritative for the domain (3.3.11); MX record has a PREFERENCE (lower values preferred) and an EXCHANGE host (3.3.9); TXT record holds descriptive text (3.3.14); an A record holds a 32-bit Internet address (3.4.1); s.5.1: domain names that end in a dot are absolute; a <character-string> may be written as a string beginning and ending with a double quote",
      url: "https://www.rfc-editor.org/rfc/rfc1035",
    },
    {
      claim: "RFC 7208: SPF records are published as DNS TXT records (3.1), begin with the version section v=spf1 (4.5), and the include mechanism references another domain's SPF record (5.2)",
      url: "https://www.rfc-editor.org/rfc/rfc7208",
    },
    {
      claim: "dig: usage dig [@server] ... [name] [type]; +short toggles a terse answer, the default being verbose; if no type argument is supplied, dig performs a lookup for an A record",
      url: "https://bind9.readthedocs.io/en/latest/manpages.html",
    },
  ],
};
