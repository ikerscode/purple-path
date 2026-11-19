const TACTIC_CORRECT = "TA0008 Lateral Movement";
const TACTIC_OPTIONS = [TACTIC_CORRECT, "TA0004 Privilege Escalation", "TA0007 Discovery", "TA0010 Exfiltration"];

const IMPACT_CORRECT =
  "The same password is also valid for the account on the other host, so one disclosure can put both hosts at risk";
const IMPACT_OPTIONS = [
  IMPACT_CORRECT,
  "Only the host where the password was disclosed is at risk, because accounts on different hosts are separate",
  "There is no extra risk, because both hosts are listed as in scope in the written authorisation",
  "The risk is limited to hosts outside the scope document, because in-scope hosts are protected by the authorisation",
];

const DEFENCE_CORRECT =
  "Give svc-backup a different, unique credential on each host, require multi-factor authentication for its interactive SSH logins where the system supports it, and restrict which accounts and which networks can reach SSH on each host";
const DEFENCE_OPTIONS = [
  DEFENCE_CORRECT,
  "Keep the same password on both hosts but make it longer, because length is what stops a password from working on a second host",
  "Rely on the firewall at the edge of the network, because both hosts sit inside it and the shared password is then safe to keep",
  "Use the same password for svc-backup on every host the team manages, so that there is only one credential to protect",
];

export default {
  id: "10-lateral",
  order: 10,
  tier: "intermediate",
  title: "One password, two hosts",
  term: "Lateral movement",
  card: {
    what: "MITRE ATT&CK describes lateral movement (tactic TA0008) as techniques that adversaries use to enter and control remote systems on a network, and says adversaries might use legitimate credentials with native network and operating system tools, which may be stealthier. One example is T1021.004, which covers using Valid Accounts to log into remote machines with Secure Shell (SSH).",
    why: "ATT&CK's page for local accounts (T1078.003) says password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of privilege escalation and lateral movement. The NCSC advises that passwords should not be re-used for different systems, and says networks with strong boundary protection but no internal security give attackers free rein to traverse the network once they have gained access.",
    example: "Two servers, one service account, one shared password: anyone who obtains that password by any means holds a valid credential for both servers. Nothing is run against any host in this exercise: you read the scope and the audit material and choose the defences. Only review systems you are authorised to review.",
  },
  world: {
    hosts: [
      {
        ip: "192.0.2.61",
        hostname: "app02.example.test",
        inScope: true,
        services: [{ port: 22, proto: "tcp", state: "open", service: "ssh", version: "" }],
      },
      {
        ip: "192.0.2.62",
        hostname: "files02.example.test",
        inScope: true,
        services: [{ port: 22, proto: "tcp", state: "open", service: "ssh", version: "" }],
      },
      {
        ip: "198.51.100.62",
        hostname: "billing01.example.test",
        inScope: false,
        services: [{ port: 22, proto: "tcp", state: "open", service: "ssh", version: "" }],
      },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional client, fictional hosts).\nStart with the written authorisation in engagement/scope.txt, then read the audit material in review/. Nothing here connects to any host.\nTools: cat, ls, and wc -l on the audit note. Type help for the built-ins.",
      "/home/analyst/engagement/scope.txt":
        "ENGAGEMENT AUTHORISATION (fictional exercise document)\n\nClient:    Brackenfield Example Ltd (fictional)\nReviewer:  A. Analyst\nSigned:    client IT director (fictional)\n\nIN SCOPE\n  192.0.2.61     app02.example.test\n  192.0.2.62     files02.example.test\n\nEXCLUSION LIST (not authorised)\n  198.51.100.62  billing01.example.test\n                 run by a third-party payment provider, which has not consented\n\nPERMITTED\n  Reading the audit material supplied in review/ on this workstation.\n\nNOT PERMITTED\n  Any connection to, or activity against, a host that is not listed under IN SCOPE.\n\nPOINT OF CONTACT\n  security@example.test - ask before doing anything this document does not cover.",
      "/home/analyst/review/audit-note.txt":
        "CONFIGURATION AUDIT NOTE (fictional exercise document)\n\nReference:    AUD-2026-0417\nPrepared by:  IT operations, Brackenfield Example Ltd (fictional)\n\nFINDING\n  The service account svc-backup has the same password configured on\n  both in-scope hosts:\n    app02.example.test\n    files02.example.test\n  The password itself, and any stored form of it, are deliberately not\n  included in this note.\n\nCAUSE\n  The configuration-management role base-accounts reads one password\n  variable and applies it to every host in the group backup-targets.\n  Both hosts are in that group.\n\nHOW THE ACCOUNT IS USED\n  Backup jobs run as svc-backup on each host. The on-call team also logs\n  in to svc-backup over SSH to administer the backup service.\n\nSTATUS\n  Nothing has been changed yet. No one has logged in to either host for\n  this review.\n",
      "/home/analyst/review/ssh-summary.txt":
        "SSH SETTINGS SUMMARY (fictional, exported by the audit tool)\nSetting names are those of sshd_config. \"not set\" means the setting is absent\nfrom the file, so the built-in default applies.\n\nhost                  PasswordAuthentication  AuthenticationMethods  AllowUsers  reachable on 22/tcp from\napp02.example.test    yes                     not set                not set     192.0.2.0/24 (the whole server network)\nfiles02.example.test  yes                     not set                not set     192.0.2.0/24 (the whole server network)",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^wc -l review/audit-note\\.txt$",
      caseSensitive: true,
      output: "25 review/audit-note.txt",
      event: "counted:note",
    },
    {
      match: "^wc -l /home/analyst/review/audit-note\\.txt$",
      caseSensitive: true,
      output: "25 /home/analyst/review/audit-note.txt",
      event: "counted:note",
    },
  ],
  outOfScope: {
    hosts: ["198.51.100.62", "billing01.example.test"],
    message:
      "That command named a host on the exclusion list in your written authorisation, so you had no permission to test it. It is run by a third party that has not consented. Testing it would first need a change to the written scope, and NIST SP 800-115 notes that the owner of a third-party network usually must also consent in writing. In this exercise the engagement ends here.",
  },
  objectives: [
    {
      id: "read-scope",
      prompt: "Read the written authorisation before anything else: cat engagement/scope.txt",
      check: { type: "event", value: "read:/home/analyst/engagement/scope.txt" },
      success: "Good. The scope lists two hosts you may review and one host on the exclusion list.",
    },
    {
      id: "read-note",
      prompt: "Read the audit note: cat review/audit-note.txt",
      check: { type: "event", value: "read:/home/analyst/review/audit-note.txt" },
      success: "The note describes the finding and deliberately leaves out the password and any stored form of it.",
    },
    {
      id: "read-ssh",
      prompt: "Read the SSH settings summary: cat review/ssh-summary.txt",
      check: { type: "event", value: "read:/home/analyst/review/ssh-summary.txt" },
      success: "The summary shows how each host accepts SSH logins and which addresses can reach the SSH port.",
    },
    {
      id: "count-hosts",
      prompt: "Type a number: on how many in-scope hosts does the audit note say svc-backup has the same password?",
      check: { type: "answer", value: ["2", "two"] },
      success: "Two: app02.example.test and files02.example.test. Both are in the configuration-management group that receives the one password variable.",
    },
    {
      id: "reach",
      prompt: "Type the network range that the summary says can reach 22/tcp on both hosts.",
      check: { type: "answer", value: ["192.0.2.0/24"] },
      success: "192.0.2.0/24, the whole server network. Both hosts are in that range, so according to the summary each can reach the other's SSH port.",
    },
    {
      id: "tactic",
      prompt: "Which ATT&CK tactic covers techniques adversaries use to enter and control remote systems on a network, such as logging in to a second host with an account found on the first?",
      check: { type: "choice", value: TACTIC_CORRECT, options: TACTIC_OPTIONS },
      success: "Lateral Movement, TA0008. ATT&CK says it consists of techniques that adversaries use to enter and control remote systems on a network.",
    },
    {
      id: "technique-ssh",
      prompt: "Type the ATT&CK technique ID for logging in to remote machines with Valid Accounts over Secure Shell (Remote Services: SSH).",
      check: { type: "answer", value: ["T1021.004"] },
      success: "T1021.004. ATT&CK says adversaries may use Valid Accounts to log into remote machines using SSH, and may then perform actions as the logged-on user.",
    },
    {
      id: "impact",
      prompt: "What does the shared password mean for the risk to the two hosts?",
      check: { type: "choice", value: IMPACT_CORRECT, options: IMPACT_OPTIONS },
      success: "Because the same password is configured on both, a password obtained for the account on one host is also a valid password for the account on the other. ATT&CK T1078.003 says password reuse may allow the abuse of local accounts across a set of machines for privilege escalation and lateral movement.",
    },
  ],
  defence: {
    prompt:
      "Which set of changes matches ATT&CK's mitigations for these techniques and the NCSC guidance on preventing lateral movement?",
    check: {
      type: "choice",
      value: DEFENCE_CORRECT,
      options: DEFENCE_OPTIONS,
    },
    explanation:
      "The finding is one password for svc-backup on two hosts that can reach each other. The NCSC says passwords should not be re-used for different systems, and that a single account should not grant access to all devices across an enterprise. ATT&CK's password-policy mitigation for local accounts (T1078.003, M1027) makes the same point for local administrator accounts: complex, unique passwords across all systems on the network. For the interactive SSH logins, ATT&CK's mitigation for T1021.004 is to require multi-factor authentication for SSH connections wherever possible (M1032), and the NCSC says that where available MFA should be enabled on administrator accounts. Another of ATT&CK's mitigations for T1021.004 is to limit which user accounts are allowed to log in via SSH (M1018); sshd_config(5) describes AllowUsers for this (by default, login is allowed for all users). Its AuthenticationMethods setting is a different control: it names the methods that must be completed for a user to be granted access, and its default is to accept any single method. The NCSC also says to constrain who can connect to an administration interface (SSH is one of its examples) and from where, and lists a dedicated management network, a VPN and an IP allow list as examples; it notes that IP allow lists can be overcome if the attacker can share or spoof the IP address space and can be difficult to maintain. For the network, the NCSC says systems that do not need to communicate with each other should be separated into different network segments, and NIST SP 800-53 SC-7(21) describes boundary protection mechanisms that isolate system components, which limits unauthorized information flows among them. The other choices keep one password valid on several hosts, lengthen a password that stays identical on both hosts, or rely on the boundary alone, when the NCSC says networks with strong boundary protection but no internal security give attackers free rein once inside.",
  },
  quiz: {
    question:
      "According to the NCSC guidance on preventing lateral movement, how does network segmentation help?",
    options: [
      "It greatly increases the difficulty for an attacker to reach their goal once in the network, because their point of entry may not have any means of reaching the target",
      "It stops attackers from entering the network in the first place, so internal controls are not needed",
      "It removes the need for unique credentials, because hosts in different segments can safely share a password",
      "It makes monitoring unnecessary, because traffic between segments cannot be seen",
    ],
    answer: 0,
    explanation:
      "The NCSC says segmentation splits a network into segments, which greatly increases the difficulty for an attacker to reach their goal once in the network, as their point of entry may not have any means of reaching the target data or system. The same guidance says to assume an attacker with sufficient time and resources will eventually be successful, says not to re-use passwords for different systems, and lists monitoring networks as a further protection.",
  },
  glossary: [
    {
      term: "Lateral movement",
      definition:
        "In MITRE ATT&CK, a tactic (TA0008) consisting of techniques that adversaries use to enter and control remote systems on a network. The NCSC describes it as what an attacker does after gaining an initial foothold: broadening and cementing that foothold while gaining further access to valuable data or systems.",
    },
    {
      term: "Valid Accounts (T1078)",
      definition:
        "ATT&CK: adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network.",
    },
    {
      term: "Remote Services: SSH (T1021.004)",
      definition:
        "ATT&CK: adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH), and may then perform actions as the logged-on user.",
    },
    {
      term: "Local account and password reuse",
      definition:
        "ATT&CK describes local accounts as those configured by an organization for use by users, remote support, services, or for administration on a single system or service, and says password reuse may allow the abuse of local accounts across a set of machines on a network.",
    },
    {
      term: "Multi-factor authentication (MFA)",
      definition:
        "The NIST SP 800-63B-4 glossary defines it as an authentication system that requires more than one distinct type of authentication factor for successful authentication.",
    },
    {
      term: "Network segmentation",
      definition:
        "The NCSC describes splitting a network into various network segments, with systems and data that do not need to communicate separated into different segments and users allowed to access a segment only where needed.",
    },
    {
      term: "Exclusion list",
      definition:
        "The list of systems that are not authorised for testing. In this level the written authorisation lists the third-party host under it.",
    },
  ],
  hints: [
    "Read the scope first, then the audit note and the SSH summary with cat. The note says what is wrong without printing the secret.",
    "For the counts and the range, read the two review files again. The scope file is not about the finding; it says which hosts you may review.",
    "A shared password is one secret valid in two places. Think about what removes the sharing, what adds a second factor, and what limits who and what can reach SSH.",
  ],
  solution: [
    "cat engagement/scope.txt",
    "cat review/audit-note.txt",
    "cat review/ssh-summary.txt",
    "2",
    "192.0.2.0/24",
    TACTIC_CORRECT,
    "T1021.004",
    IMPACT_CORRECT,
    DEFENCE_CORRECT,
  ],
  sources: [
    {
      claim:
        "MITRE ATT&CK tactic TA0008 Lateral Movement: consists of techniques that adversaries use to enter and control remote systems on a network; adversaries might install their own remote access tools or use legitimate credentials with native network and operating system tools, which may be stealthier",
      url: "https://attack.mitre.org/tactics/TA0008/",
    },
    {
      claim: "MITRE ATT&CK enterprise tactics list: TA0004 Privilege Escalation, TA0007 Discovery, TA0008 Lateral Movement, TA0010 Exfiltration",
      url: "https://attack.mitre.org/tactics/enterprise/",
    },
    {
      claim:
        "MITRE ATT&CK T1021.004 Remote Services: SSH: adversaries may use Valid Accounts to log into remote machines using SSH and may then perform actions as the logged-on user; mitigation M1032: require multi-factor authentication for SSH connections wherever possible; mitigation M1018: limit which user accounts are allowed to login via SSH",
      url: "https://attack.mitre.org/techniques/T1021/004/",
    },
    {
      claim:
        "MITRE ATT&CK T1078 Valid Accounts: adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion; compromised credentials may be used to bypass access controls placed on various resources on systems within the network",
      url: "https://attack.mitre.org/techniques/T1078/",
    },
    {
      claim:
        "MITRE ATT&CK T1078.003 Local Accounts: local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service; password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement; mitigation M1027: ensure that local administrator accounts have complex, unique passwords across all systems on the network",
      url: "https://attack.mitre.org/techniques/T1078/003/",
    },
    {
      claim:
        "NCSC, Preventing Lateral Movement, What is lateral movement? and Why protect against lateral movement?: after an initial foothold an attacker will typically look to broaden and cement it while gaining further access to valuable data or systems; you should assume an attacker with sufficient time and resources will eventually be successful; networks with strong boundary protection but no internal security give attackers free rein to traverse the network once they have gained access",
      url: "https://www.ncsc.gov.uk/guidance/preventing-lateral-movement",
    },
    {
      claim:
        "NCSC, Preventing Lateral Movement, step 2 (Deploy good authentication practices): do not re-use passwords for different systems; ensure that a single account cannot grant access to all devices and components across an enterprise, particularly if those accounts are privileged",
      url: "https://www.ncsc.gov.uk/guidance/preventing-lateral-movement",
    },
    {
      claim:
        "NCSC, Preventing Lateral Movement, step 6 (Segregate networks as sets) and step 7 (Monitor networks): network segmentation splits a network into segments and greatly increases the difficulty for an attacker to reach their goal once in the network, as their point of entry may not have any means of reaching the target data or system; systems and data that do not need to communicate should be separated into different segments and users allowed to access a segment only where needed; it is vital to monitor networks",
      url: "https://www.ncsc.gov.uk/guidance/preventing-lateral-movement",
    },
    {
      claim:
        "NCSC, Secure system administration, Protect your administration interfaces: remote management protocols such as SSH are administration interfaces; constrain who can connect and from where, for example with a dedicated management network, a VPN or an IP allow list; IP allow lists can be overcome if the attacker is able to share the IP address space, or spoof it, and can be difficult to maintain; where available, MFA should be enabled on administrator accounts",
      url: "https://www.ncsc.gov.uk/collection/secure-system-administration/protect-your-administration-interfaces",
    },
    {
      claim:
        "NIST SP 800-53 Rev. 5, SC-7(21) Boundary Protection | Isolation of System Components: employ boundary protection mechanisms to isolate system components; such isolation limits unauthorized information flows among system components",
      url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf",
    },
    {
      claim:
        "NIST SP 800-63B-4 glossary: multi-factor authentication (MFA) is an authentication system that requires more than one distinct type of authentication factor for successful authentication",
      url: "https://pages.nist.gov/800-63-4/sp800-63b.html",
    },
    {
      claim:
        "sshd_config(5): AllowUsers, if specified, allows login only for user names matching one of the patterns, and by default login is allowed for all users; AuthenticationMethods lists the methods that must be completed for access, and the default is to accept any single authentication method; PasswordAuthentication specifies whether password authentication is allowed and the default is yes",
      url: "https://man.openbsd.org/sshd_config",
    },
    {
      claim:
        "NIST SP 800-115 section 6.5: if the organization does not control part or all of its network, such as having a portion of its systems housed on a third party's network, the owner of the other network usually must also consent in writing to the assessment plan",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf",
    },
  ],
};
