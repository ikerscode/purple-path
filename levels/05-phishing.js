export default {
  id: "05-phishing",
  order: 5,
  tier: "beginner",
  title: "Read the message",
  term: "Phishing",
  card: {
    what: "In MITRE ATT&CK, all forms of phishing are electronically delivered social engineering, and adversaries may pose as a trusted source or spoof the sender's identity. The NCSC lists tell-tale signs such as authority, urgency, emotion, scarcity and current events.",
    why: "RFC 9989 notes that abusive email often makes unauthorised, deceptive use of a domain in the From field. SPF checks whether the sending server is authorised to use the domain in the SMTP MAIL FROM identity, and DKIM checks a signature added by a signing domain, but neither is tied directly to the From field. DMARC ties the domain in the From field to those checks and lets the domain owner say what it would like done with mail that fails.",
    example: "A message shows From: helpdesk@fernleigh.example, but the server that delivered it is not in fernleigh.example's SPF record.",
  },
  world: {
    hosts: [{ ip: "192.0.2.25", hostname: "mx1.fernleigh.example", inScope: true, services: [] }],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional client, fictional domain).\nStart with engagement/brief.txt.\nTools: cat, ls and dig. dig is modelled with +short and the TXT type only, for example: dig +short TXT fernleigh.example",
      "/home/analyst/engagement/brief.txt":
        "EXERCISE BRIEF (fictional)\n\nClient:  Fernleigh Example Ltd (fictional), domain fernleigh.example\n\nA member of staff forwarded one suspicious message: inbox/forwarded.eml\n\nYOUR TASK\n  Analyse the message source and the client's own public DNS records.\n\nNOT PERMITTED\n  Opening the link in the message.\n  Looking up, scanning or otherwise contacting any host the message names\n  (the link target, the sending server or the Reply-To domain).\n  Report those hosts instead.",
      "/home/analyst/inbox/forwarded.eml":
        "Return-Path: <helpdesk@fernleigh.example>\nAuthentication-Results: mx1.fernleigh.example;\n\tspf=fail smtp.mailfrom=helpdesk@fernleigh.example;\n\tdkim=none;\n\tdmarc=fail header.from=fernleigh.example\nReceived: from mailer.fernleigh-helpdesk.test (mailer.fernleigh-helpdesk.test [198.51.100.25])\n\tby mx1.fernleigh.example (Postfix) with ESMTP id 4F2A91B0C\n\tfor <j.doyle@fernleigh.example>; Tue, 10 Mar 2026 09:14:02 +0000 (UTC)\nFrom: \"Fernleigh IT Helpdesk\" <helpdesk@fernleigh.example>\nReply-To: \"IT Helpdesk\" <helpdesk@fernleigh-helpdesk.test>\nTo: j.doyle@fernleigh.example\nSubject: Action required: mailbox disabled within 24 hours\nDate: Tue, 10 Mar 2026 09:13:58 +0000\nMessage-ID: <20260310091358.7731@mailer.fernleigh-helpdesk.test>\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n<html><body>\n<p>Dear user,</p>\n<p>Your mailbox is over its limit and will be disabled within 24 hours.\nConfirm your password now to keep access.</p>\n<p><a href=\"https://portal.fernleigh-helpdesk.test/reset\">https://mail.fernleigh.example/reset</a></p>\n<p>IT Helpdesk</p>\n</body></html>",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^dig(?=.* \\+short( |$))(?=.* txt( |$))(?=.* _dmarc\\.fernleigh\\.example\\.?( |$))( \\+short| txt| _dmarc\\.fernleigh\\.example\\.?){3}$",
      output: "\"v=DMARC1; p=none; rua=mailto:dmarc-reports@fernleigh.example\"",
      event: "dns:dmarc",
    },
    {
      match: "^dig(?=.* \\+short( |$))(?=.* txt( |$))(?=.* fernleigh\\.example\\.?( |$))( \\+short| txt| fernleigh\\.example\\.?){3}$",
      output: "\"v=spf1 ip4:192.0.2.25 -all\"",
      event: "dns:spf",
    },
  ],
  outOfScope: {
    hosts: ["fernleigh-helpdesk.test", "portal.fernleigh-helpdesk.test", "mailer.fernleigh-helpdesk.test", "198.51.100.25"],
    message:
      "That command named a host that appears in the suspicious message (its link, its sending server or its Reply-To domain). Your written brief for this task covers reading the message and the client's own public DNS records only, and it does not permit looking up, scanning or contacting those hosts. In this exercise the engagement ends as soon as such a host is named.",
  },
  objectives: [
    {
      id: "read-email",
      prompt: "Read the forwarded message source: cat inbox/forwarded.eml",
      check: { type: "event", value: "read:/home/analyst/inbox/forwarded.eml" },
      success: "This is the raw message: header fields first, then a blank line, then the body. The Authentication-Results field was added by the client's own mail server, mx1.fernleigh.example.",
    },
    {
      id: "read-spf",
      prompt: "Look up the client's SPF record, which is a TXT record on its domain: dig +short TXT fernleigh.example",
      check: { type: "event", value: "dns:spf" },
      success: "RFC 7208 says SPF records are published as DNS TXT records (section 3.1) and start with v=spf1 (section 4.5). ip4:192.0.2.25 authorises one address (section 5.6). The all mechanism always matches and is used as the rightmost mechanism to give an explicit default, and the - qualifier makes that default a fail result (sections 4.6.2 and 5.1).",
    },
    {
      id: "read-dmarc",
      prompt: "Look up the client's DMARC policy record: dig +short TXT _dmarc.fernleigh.example",
      check: { type: "event", value: "dns:dmarc" },
      success: "RFC 9989 says a DMARC Policy Record is a DNS TXT record at the domain name with _dmarc added in front (section 4.5). The p tag is the Domain Owner Assessment Policy and rua says where aggregate reports go (section 4.7).",
    },
    {
      id: "spf-result",
      prompt: "In the Authentication-Results field, what result is reported for spf? Type one word.",
      check: { type: "answer", value: ["fail"] },
      success: "SPF fail is an explicit statement that the client is not authorised to use the domain in the given identity (RFC 7208 section 2.6.4). The sending address 198.51.100.25 is not in the record, and the record ends in -all. RFC 7208 section 8.4 says what to do with a fail message is a matter of local policy.",
    },
    {
      id: "link-mismatch",
      prompt: "Compare the link text with the link address (the href) in the HTML part. What does the message do?",
      check: {
        type: "choice",
        value: "The text shown to the reader names one domain, but the link's address points to a different domain",
        options: [
          "The text shown to the reader and the link's address name the same domain",
          "The link's address points to the client's own domain",
          "The text shown to the reader names one domain, but the link's address points to a different domain",
        ],
      },
      success: "CISA says that if the links in an email do not match the text that appears, the link may be spoofed, and that a malicious URL may use a variation in spelling or a different domain.",
    },
    {
      id: "reply-to",
      prompt: "If a staff member pressed Reply, where would the reply go?",
      check: {
        type: "choice",
        value: "To the address in the Reply-To field, which is on a different domain from the From address",
        options: [
          "To the address in the From field, because a Reply-To field is ignored",
          "To the address in the Reply-To field, which is on a different domain from the From address",
          "To the address in the Return-Path field, which is the client's own helpdesk",
        ],
      },
      success: "RFC 5322 section 3.6.2: when a Reply-To field is present it indicates the addresses to which the author suggests replies be sent. Without one, replies go by default to the From mailbox. Here the two are on different domains.",
    },
    {
      id: "urgency",
      prompt: "The message says the mailbox will be disabled \"within 24 hours\". Which of the NCSC's tell-tale signs is that wording?",
      check: {
        type: "choice",
        value: "Urgency",
        options: ["Authority", "Scarcity", "Urgency", "Current events"],
      },
      success: "The NCSC's example of urgency is being told you have a limited time to respond, such as \"within 24 hours\" or \"immediately\". Its authority sign is a message claiming to be from someone official.",
    },
    {
      id: "report",
      prompt: "The staff member is not sure the message is a scam. What does the NCSC advise?",
      check: {
        type: "choice",
        value: "Forward it to the NCSC at report@phishing.gov.uk and do not click any links in it",
        options: [
          "Click the link to check whether the website is genuine",
          "Reply to the address in the message to ask whether it is real",
          "Do nothing, because the NCSC only wants emails you are certain are scams",
          "Forward it to the NCSC at report@phishing.gov.uk and do not click any links in it",
        ],
      },
      success: "The NCSC page on reporting scam emails says to forward an email you are not quite sure about, that you can send emails that feel suspicious even if you are not certain, and not to click links in a suspicious email. Its advice on checking a message is to contact the organisation directly, not using the numbers or address in the message.",
    },
  ],
  defence: {
    prompt:
      "The client's DMARC record is p=none, and the forged message was delivered. Which approach does RFC 9989 describe for getting from there to a policy that asks receivers to act on mail that fails?",
    check: {
      type: "choice",
      value:
        "Read the aggregate reports sent to the rua address, fix any legitimate mail that fails SPF or DKIM alignment, then decide whether to move p= to quarantine or reject",
      options: [
        "Keep p=none, because it asks receivers to reject mail that fails",
        "Switch straight to p=reject without reading any aggregate reports",
        "Read the aggregate reports sent to the rua address, fix any legitimate mail that fails SPF or DKIM alignment, then decide whether to move p= to quarantine or reject",
        "Publish p=reject and treat it as a guarantee that every receiver will reject mail that fails",
      ],
    },
    explanation:
      "RFC 9989 section 4.7 says that for p=none the Domain Owner offers no expression of preference, so it does not ask receivers to reject anything. Sections 5.1.4 and 5.1.5 say Domain Owners usually start at p=none with a rua mailbox so the aggregate reports can be used to audit their own mail streams, and section 5.1.6 says shortcomings in legitimate mail must be addressed before publishing a policy of Enforcement. Section 5.1.7 says the decision to move to Enforcement comes once the owner is satisfied it is authenticating all of its mail, and that, depending on its cadence for sending mail, it may take many months of reports. Section 5.4 says the final handling of any message is a matter of local policy for the Mail Receiver, and that receivers may accept mail that fails even when the published policy is reject.",
  },
  quiz: {
    question: "In DMARC (RFC 9989), where does the Author Domain come from?",
    options: [
      "The domain in the SMTP MAIL FROM address",
      "The domain of the server named in the Received field",
      "The domain in the Reply-To field",
      "The domain in the RFC5322.From header field",
    ],
    answer: 3,
    explanation:
      "RFC 9989 section 3.2.2 defines the Author Domain as the domain name of the apparent author as extracted from the RFC5322.From header field. For DMARC, SPF counts only through the MAIL FROM identity (section 4.4.2), and DKIM through the signing domain in the d tag (section 4.4.1); DMARC then requires one of those authenticated identifiers to align with the Author Domain. The definition does not draw the Author Domain from the Received or Reply-To fields.",
  },
  glossary: [
    {
      term: "Phishing",
      definition:
        "MITRE ATT&CK T1566: adversaries send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. It can be targeted (spearphishing) or non-targeted, and may involve posing as a trusted source or spoofing the sender's identity.",
    },
    {
      term: "SPF (Sender Policy Framework)",
      definition:
        "RFC 7208: a domain publishes a DNS TXT record starting v=spf1 that says which hosts are authorised to send for it. A fail result is an explicit statement that the client is not authorised to use the domain in the given identity (the MAIL FROM or HELO identity).",
    },
    {
      term: "DKIM (DomainKeys Identified Mail)",
      definition:
        "RFC 6376: a signing domain claims some responsibility for a message by adding a cryptographic signature, and a verifier retrieves the public key from the signer's domain in DNS, in a TXT record under the _domainkey subdomain. In an Authentication-Results field, dkim=none means the message was not signed (RFC 8601 section 2.7.1).",
    },
    {
      term: "DMARC and the Author Domain",
      definition:
        "RFC 9989: DMARC lets a domain owner publish, in a TXT record at _dmarc.<domain>, a message handling preference (p=none, quarantine or reject) for mail whose RFC5322.From domain fails validation, and ask for reports (rua for aggregate reports). A message passes when an SPF or DKIM authenticated identifier aligns with the Author Domain. Final handling is a matter of local policy for the receiver.",
    },
    {
      term: "Authentication-Results",
      definition:
        "RFC 8601: a header field in which a receiving mail system records the results of authentication checks such as spf, dkim and dmarc, starting with an identifier for the system that did the checking.",
    },
  ],
  hints: [
    "Start with the brief: cat engagement/brief.txt, then read the message: cat inbox/forwarded.eml",
    "dig is modelled with +short and the TXT type for the client's own domain only, for example: dig +short TXT fernleigh.example",
    "Do not look up or contact any host the message names. Read what the message says about itself, and report those hosts instead.",
  ],
  solution: [
    "cat inbox/forwarded.eml",
    "dig +short TXT fernleigh.example",
    "dig +short TXT _dmarc.fernleigh.example",
    "fail",
    "The text shown to the reader names one domain, but the link's address points to a different domain",
    "To the address in the Reply-To field, which is on a different domain from the From address",
    "Urgency",
    "Forward it to the NCSC at report@phishing.gov.uk and do not click any links in it",
    "Read the aggregate reports sent to the rua address, fix any legitimate mail that fails SPF or DKIM alignment, then decide whether to move p= to quarantine or reject",
  ],
  sources: [
    {
      claim: "MITRE ATT&CK T1566 Phishing: all forms of phishing are electronically delivered social engineering; it can be targeted (spearphishing) or non-targeted; it may involve posing as a trusted source and email spoofing of the sender's identity; mitigation M1054 says use anti-spoofing and email authentication (SPF, DKIM) and enabling these through policies such as DMARC may let recipients perform similar filtering",
      url: "https://attack.mitre.org/techniques/T1566/",
    },
    {
      claim: "NCSC, how to spot a scam email, text message or call: scams often feature authority, urgency (for example 'within 24 hours' or 'immediately'), emotion, scarcity and current events; to check a message, contact the organisation directly and do not use the numbers or address in the message",
      url: "https://www.ncsc.gov.uk/collection/phishing-scams/spot-scams",
    },
    {
      claim: "NCSC, report a scam email: forward an email you are not quite sure about to the reporting address (report@phishing.gov.uk); you can forward emails that feel suspicious even if you are not certain; do not click on any links in a suspicious email",
      url: "https://www.ncsc.gov.uk/collection/phishing-scams/report-scam-email",
    },
    {
      claim: "CISA, avoiding social engineering and phishing attacks: if links in an email do not match the text that appears, the link may be spoofed; a malicious website's URL may use a variation in spelling or a different domain; a sender's address may imitate a legitimate business",
      url: "https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks",
    },
    {
      claim: "RFC 5322 section 2.1: a message is a header section followed optionally by a body, separated from the header section by an empty line; section 3.6.2: the From field specifies the author of the message; when a Reply-To field is present it indicates the addresses to which the author suggests replies be sent, and without it replies go by default to the From mailbox",
      url: "https://www.rfc-editor.org/rfc/rfc5322",
    },
    {
      claim: "RFC 5321 section 4.4: an SMTP server inserts a Received line whose FROM clause should contain the name given in EHLO and an address literal of the source IP address; final delivery inserts a Return-path line preserving the MAIL FROM reverse-path",
      url: "https://www.rfc-editor.org/rfc/rfc5321",
    },
    {
      claim: "RFC 7208 (SPF): records are published as DNS TXT records (3.1) and begin with v=spf1 (4.5); the MAIL FROM identity is checked (2.4); qualifiers + - ~ ? give pass, fail, softfail, neutral (4.6.2); a fail result is an explicit statement that the client is not authorised to use the domain in the given identity (2.6.4), and its disposition is a matter of local policy (8.4); the all mechanism always matches and is used rightmost as an explicit default (5.1); ip4 mechanism (5.6)",
      url: "https://www.rfc-editor.org/rfc/rfc7208",
    },
    {
      claim: "RFC 6376 (DKIM): the signing domain claims responsibility for a message through a cryptographic signature and the verifier retrieves the public key by querying the signer's domain (Abstract); DKIM keys are stored in TXT records in a _domainkey subdomain (section 3.6.2.1 for the namespace and section 3.6.2.2 for the record type)",
      url: "https://www.rfc-editor.org/rfc/rfc6376",
    },
    {
      claim: "RFC 8601 (Authentication-Results): (2.1) added at the top of the message as it transits MTAs that do authentication checks; header field layout authserv-id then method=result with property=value pairs (2.2); dkim result none means the message was not signed (2.7.1); spf results and the smtp.mailfrom property (2.7.2)",
      url: "https://www.rfc-editor.org/rfc/rfc8601",
    },
    {
      claim: "RFC 9989 (DMARC, obsoletes RFC 7489): Author Domain is taken from RFC5322.From (3.2.2); policy record is a TXT record at _dmarc.<domain> (4.1, 4.5); p none means no expression of preference, quarantine, reject, rua tag (4.7); alignment of SPF or DKIM authenticated identifiers with the Author Domain (4.4, 4.4.1, 4.4.2), where DMARC relies solely on SPF validation of the MAIL FROM identity (4.4.2); (section 1) SPF and DKIM are not directly associated with the RFC5322.From domain, and abusive email often uses the From domain deceptively; starting at p=none with reports, remediating legitimate mail before Enforcement, and deciding when to move to Enforcement, which depending on the owner's cadence for sending mail may take many months of reports (5.1.4 to 5.1.7); final handling is local policy and receivers may accept failing mail even under p=reject (5.4); dmarc result names fail/none/pass (9.2)",
      url: "https://www.rfc-editor.org/rfc/rfc9989",
    },
  ],
};
