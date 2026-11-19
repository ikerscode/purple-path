const RULE_NGINX_TEST = "(root) NOPASSWD: /usr/sbin/nginx -t";
const RULE_NGINX_RELOAD = "(root) NOPASSWD: /usr/bin/systemctl reload nginx.service";
const RULE_VIM = "(root) NOPASSWD: /usr/bin/vim";
const RULES = [RULE_NGINX_TEST, RULE_NGINX_RELOAD, RULE_VIM];

const WHY_BROAD =
  "No arguments are given, so analyst may run vim with any arguments, and once sudo runs a program that program is free to do whatever it pleases, including run other programs";
const WHY_OPTIONS = [
  WHY_BROAD,
  "The (root) part means the rule only works while analyst is already logged in as root",
  "NOPASSWD limits the rule to one file, so the editor can open only that file",
  "Because the rule names a full path, sudo limits what the program can do to the files in that directory",
];

const IMPACT =
  "The elevated privileges are not dropped, so functions the program offers, which may include reading files, writing files and starting a shell, are performed as the privileged user";
const IMPACT_OPTIONS = [
  IMPACT,
  "The privileges are dropped as soon as the program starts, so only the file named on the command line can be affected",
  "GTFOBins lists vim as a vulnerable program, so installing a patched version makes the rule safe",
  "GTFOBins only covers programs run by an unprivileged user, so sudo does not change what the program can do",
];

const DEFENCE_CORRECT = "analyst ALL=(root) sudoedit /etc/nginx/conf.d/shop.conf";
const DEFENCE_OPTIONS = [
  DEFENCE_CORRECT,
  "analyst ALL=(root) NOPASSWD: /usr/bin/vim /etc/nginx/conf.d/shop.conf",
  "analyst ALL=(ALL) NOPASSWD: ALL",
  "analyst ALL=(root) NOPASSWD: /usr/bin/less /etc/nginx/conf.d/shop.conf",
];

export default {
  id: "09-privesc",
  order: 9,
  tier: "intermediate",
  title: "Least privilege in sudo",
  term: "Privilege escalation (a sudo rule that is too broad)",
  card: {
    what: "MITRE ATT&CK describes the privilege escalation tactic (TA0004) as the adversary trying to gain higher-level permissions. On Linux, sudo lets an administrator give certain users the ability to run some or all commands as root or another user, and ATT&CK technique T1548.003 covers use of the sudoers file to elevate privileges, noting that the file can also say when not to prompt for a password.",
    why: "The sudoers manual says that once sudo executes a program, that program is free to do whatever it pleases, including run other programs, and that common programs that permit shell escapes include shells, editors, paginators, mail and terminal programs. A rule that names an editor is therefore wider than it looks. NIST SP 800-53 control AC-6 asks for the principle of least privilege: allowing only the authorized accesses that are necessary to accomplish assigned organizational tasks.",
    example: "A rule that lets one user run /usr/bin/vim as root with no password is not the same as \"edit one file\". GTFOBins records, for programs such as vi, that a function performed through sudo is performed by the privileged user because the acquired privileges are not dropped. Nothing is run through sudo in this exercise: you read the rules and choose the fix. Only review systems you are authorised to review.",
  },
  world: {
    hosts: [
      { ip: "192.0.2.50", hostname: "app01.example.test", inScope: true, services: [] },
      { ip: "198.51.100.60", hostname: "hrdb01.example.test", inScope: false, services: [] },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional web shop, fictional host).\nYou are reviewing the sudo rules that apply to your own account on app01. Nothing is run through sudo here, and nothing connects to a live system.\nStart with brief.txt. Tools: sudo -l (the listing only), cat and ls. Type help for the built-ins.",
      "/home/analyst/brief.txt":
        "REVIEW BRIEF (fictional exercise document)\n\nClient:   Brackenfield Example Ltd (fictional)\nHost:     app01.example.test (192.0.2.50), the web server you are logged in to as the user analyst\nTask:     Review the sudo rules that apply to analyst: what they allow, which one is too broad, and what the entry should say instead.\n\nBUSINESS NEED (ticket OPS-2291)\n  The web operator must edit the shop's nginx configuration file /etc/nginx/conf.d/shop.conf, test the configuration, and reload nginx. Nothing else.\n\nIN THE REVIEW\n  sudo -l                         the listing of what analyst may run\n  review/sudoers-90-ops.txt       an exported copy of the sudoers fragment /etc/sudoers.d/90-ops\n  The general Defaults that sudo -l also shows come from the main sudoers file, which is not part of the export and is not judged here.\n\nNOT PART OF THIS REVIEW\n  hrdb01.example.test (198.51.100.60), run by another team.",
      "/home/analyst/review/sudoers-90-ops.txt":
        "# /etc/sudoers.d/90-ops\n# Exported copy supplied for the review (fictional).\n# Ticket OPS-2291: the web operator maintains the shop's nginx setup.\n\n# 1: test the configuration\nanalyst ALL=(root) NOPASSWD: /usr/sbin/nginx -t\n# 2: reload nginx\nanalyst ALL=(root) NOPASSWD: /usr/bin/systemctl reload nginx.service\n# 3: edit the configuration (\"so edits are quick\")\nanalyst ALL=(root) NOPASSWD: /usr/bin/vim\n",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^sudo (-l|--list)$",
      caseSensitive: true,
      output:
        "Matching Defaults entries for analyst on app01:\n    env_reset, mail_badpass, use_pty\n\nUser analyst may run the following commands on app01:\n" +
        RULES.map((r) => `    ${r}`).join("\n"),
      event: "listed:sudo",
    },
  ],
  outOfScope: {
    hosts: ["198.51.100.60", "hrdb01.example.test"],
    message:
      "That command named hrdb01, a host that your review brief lists as not part of this review. It is run by another team, and the brief limits the work to app01 and the exported files. In this exercise the review ends as soon as that host's name or address is named.",
  },
  objectives: [
    {
      id: "list-rules",
      prompt: "List what the box says analyst may run with sudo: sudo -l",
      check: { type: "event", value: "listed:sudo" },
      success:
        "That is the layout sudo prints: the Defaults that apply, then, for these rules, one line each showing who the command runs as, any tag such as NOPASSWD, and the command with any arguments written in the rule. sudoers(5) says that by default, if NOPASSWD is applied to any of a user's entries for the current host, the user can run sudo -l without a password, which is why no password was asked.",
    },
    {
      id: "read-fragment",
      prompt: "Read the sudoers fragment the three lines come from: cat review/sudoers-90-ops.txt",
      check: { type: "event", value: "read:/home/analyst/review/sudoers-90-ops.txt" },
      success:
        "Each rule line says who (analyst), on which hosts (ALL), as whom ((root)), with which tag (NOPASSWD), and which command. Rules 1 and 2 name a program with arguments. Rule 3 names a program and nothing else.",
    },
    {
      id: "count-nopasswd",
      prompt: "Type a number: how many of the listed rules let analyst run a command as root without being asked for a password?",
      check: { type: "answer", value: ["3", "three"] },
      success:
        "Three. sudoers(5) says that by default sudo requires a user to authenticate before running a command, and that the NOPASSWD tag changes this for the commands it applies to.",
    },
    {
      id: "which-rule",
      prompt: "Which listed rule gives analyst the most room?",
      check: { type: "choice", value: RULE_VIM, options: RULES },
      success:
        "The third. The first two each name one program with fixed arguments. The third names only the program, and the business need in the brief is to edit one file.",
    },
    {
      id: "why-broad",
      prompt: "Why is that rule wider than the ticket's \"edit one file\"?",
      check: { type: "choice", value: WHY_BROAD, options: WHY_OPTIONS },
      success:
        "sudoers(5) says that if no command line arguments are specified the user may run the command with any arguments, and that once sudo executes a program the program is free to do whatever it pleases, including run other programs. It lists editors among the common programs that permit shell escapes, which let a user bypass sudo's access control and logging.",
    },
    {
      id: "impact",
      prompt: "What does GTFOBins say happens to a program's functions when it is run through sudo?",
      check: { type: "choice", value: IMPACT, options: IMPACT_OPTIONS },
      success:
        "GTFOBins says, for the functions it lists, that the function is performed by the privileged user if executed via sudo because the acquired privileges are not dropped. Its vi entry lists a shell, file write and file read, and its vim entry inherits from vi. GTFOBins also says it is not a list of exploits and that the programs it lists are not vulnerable per se.",
    },
    {
      id: "technique",
      prompt: "Type the MITRE ATT&CK technique ID for \"Sudo and Sudo Caching\" (a sub-technique of Abuse Elevation Control Mechanism).",
      check: { type: "answer", value: ["T1548.003"] },
      success:
        "T1548.003. ATT&CK says adversaries may use the sudoers file to elevate privileges, and that the file can specify when not to prompt for a password with a line such as user1 ALL=(ALL) NOPASSWD: ALL.",
    },
  ],
  defence: {
    prompt:
      "Replace the third rule so that analyst can still edit /etc/nginx/conf.d/shop.conf and nothing more. Which entry matches sudoers(5), NIST SP 800-53 AC-6 and the ATT&CK mitigations for T1548.003? (Assume analyst has no write access to the directory /etc/nginx/conf.d.)",
    check: {
      type: "choice",
      value: DEFENCE_CORRECT,
      options: DEFENCE_OPTIONS,
    },
    explanation:
      "The ticket needs three things: test the nginx configuration, reload nginx, and edit one file. Rules 1 and 2 already name a program with fixed arguments, and sudoers(5) says that when a command has arguments in the rule they must match those the user gives. For editing, sudoers(5) says sudoedit is a better solution to running editors via sudo, and that in the specific case of an editor a safer approach is to give the user permission to run sudoedit. With sudoedit the editor runs with the permissions of the invoking user, not root, on a temporary copy of the file, and the file is updated with the copy after editing. sudoers(5) also says users should never be granted sudoedit permission to edit a file that resides in a directory the user has write access to, which is why the prompt assumes analyst cannot write to /etc/nginx/conf.d. The replacement rule leaves out NOPASSWD: ATT&CK's mitigation advice for T1548.003 says that by requiring a password an adversary with terminal access must know the password to run anything in the sudoers file, and that the sudoers file should be strictly edited so that passwords are always required and users can't spawn risky processes as users with higher privilege. By the same advice, rules 1 and 2 should also lose NOPASSWD; this step replaces only rule 3. The other entries still run an editor or a pager as root (fixing its arguments does not limit what the program can do once it runs, and sudoers(5) lists editors and paginators among programs that permit shell escapes) or allow every command, which is the example line ATT&CK gives. NCSC describes Just enough Administration as another way of describing least privilege, and says over-zealous permissions are unnecessary and add risk.",
  },
  quiz: {
    question:
      "According to the sudoers manual, what is different about editing a file with sudoedit compared with running an editor through sudo?",
    options: [
      "The editor runs with the permissions of the invoking user on a temporary copy of the file, and the file is updated with the copy after editing",
      "The editor runs as root, but sudo blocks the editor from starting other programs",
      "The editor opens the file read-only, so the file can never be changed",
      "The editor runs as root on the original file, with extra logging switched on",
    ],
    answer: 0,
    explanation:
      "sudoers(5) says that, unlike other sudo commands, the editor is run with the permissions of the invoking user and with the environment unmodified, on a temporary copy, and that the file is updated with the contents of the temporary copy after it has been edited. It does not run the editor as root, and the file can be changed.",
  },
  glossary: [
    {
      term: "Privilege escalation",
      definition:
        "In MITRE ATT&CK, a tactic (TA0004) in which the adversary is trying to gain higher-level permissions.",
    },
    {
      term: "sudo and the sudoers file",
      definition:
        "ATT&CK quotes sudo as allowing a system administrator to delegate authority to give certain users the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments. The sudoers file says which users may run which commands as which users.",
    },
    {
      term: "NOPASSWD",
      definition:
        "A sudoers tag. sudoers(5) says that by default sudo requires that a user authenticate before running a command and that this can be modified via the NOPASSWD tag. By default, if NOPASSWD is applied to any of a user's entries for the current host, the user can run sudo -l without a password.",
    },
    {
      term: "Shell escape",
      definition:
        "A way for a program that sudo has started to run other programs. sudoers(5) says this lets a user bypass sudo's access control and logging, and that common programs that permit shell escapes include shells, editors, paginators, mail and terminal programs.",
    },
    {
      term: "sudoedit",
      definition:
        "A built-in sudoers command (written without a leading path) that permits a user to run sudo with the -e option, or as sudoedit, to edit files. The editor runs with the permissions of the invoking user on a temporary copy, and the file is updated afterwards. sudoers(5) says sudoedit is a better solution to running editors via sudo.",
    },
    {
      term: "Least privilege",
      definition:
        "NIST SP 800-53 AC-6: allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks. NCSC describes Just enough Administration as another way of describing the concept of least privilege.",
    },
    {
      term: "GTFOBins",
      definition:
        "A curated list of Unix-like executables that can be used to bypass local security restrictions in misconfigured systems. The project says it is not a list of exploits and that the programs listed are not vulnerable per se.",
    },
  ],
  hints: [
    "Run sudo -l, then read the fragment with cat. Compare what the rules allow with what the ticket in the brief needs.",
    "Each rule names a program and, in some cases, arguments that must match. A program written with no arguments can be run with any arguments.",
    "One rule names a general-purpose program rather than a task. The card says what sudoers(5) says about editors, and what GTFOBins says about running such programs through sudo.",
  ],
  solution: [
    "sudo -l",
    "cat review/sudoers-90-ops.txt",
    "3",
    RULE_VIM,
    WHY_BROAD,
    IMPACT,
    "T1548.003",
    DEFENCE_CORRECT,
  ],
  sources: [
    {
      claim:
        "sudoers(5), SECURITY NOTES, Preventing shell escapes: once sudo executes a program, that program is free to do whatever it pleases, including run other programs; it is not uncommon for a program to allow shell escapes, which lets a user bypass sudo's access control and logging; common programs that permit shell escapes include shells, editors, paginators, mail, and terminal programs; sudoedit is a better solution to running editors via sudo; in the specific case of an editor, a safer approach is to give the user permission to run sudoedit",
      url: "https://www.sudo.ws/docs/man/sudoers.man/",
    },
    {
      claim:
        "sudoers(5), SUDOERS FILE FORMAT (Aliases, Cmnd_List): if no command line arguments are specified, the user may run the command with any arguments they choose; if a Cmnd has associated command line arguments, the arguments in the Cmnd must match those given by the user on the command line; sudoedit is a built-in command that must be specified without a leading path and may take command line arguments just as a normal command does",
      url: "https://www.sudo.ws/docs/man/sudoers.man/",
    },
    {
      claim:
        "sudoers(5), SECURITY NOTES, Secure editing: unlike other sudo commands, the editor is run with the permissions of the invoking user and with the environment unmodified; the editor runs as the invoking user, not root, on a temporary copy of the file, and the file is updated with the contents of the temporary copy after editing; users should never be granted sudoedit permission to edit a file that resides in a directory the user has write access to",
      url: "https://www.sudo.ws/docs/man/sudoers.man/",
    },
    {
      claim:
        "sudoers(5), SUDOERS FILE FORMAT, Tag_Spec (PASSWD and NOPASSWD): by default sudo requires that a user authenticate before running a command, and the NOPASSWD tag modifies this; by default, if NOPASSWD is applied to any of a user's entries for the current host, the user is able to run sudo -l without a password (SUDOERS OPTIONS, listpw: the default value is any, meaning at least one entry must have NOPASSWD to avoid a password prompt)",
      url: "https://www.sudo.ws/docs/man/sudoers.man/",
    },
    {
      claim:
        "sudo(8): -l (--list) with no command lists the privileges of the invoking user on the current host, and a longer list format is used if the option is given more than once; -e (--edit) edits files instead of running a command, using the string sudoedit when consulting the security policy",
      url: "https://www.sudo.ws/docs/man/sudo.man/",
    },
    {
      claim:
        "sudo 1.9.17p2 source, plugins/sudoers/display.c: the listing prints \"Matching Defaults entries for <user> on <host>:\", the entries indented four spaces, a blank line, then \"User <user> may run the following commands on <host>:\" followed by lines of the form \"    (<runas>) <command>\", with the runas user in parentheses; separate rules print on separate lines, and commands of one rule that share the same runas user are joined by commas on one line",
      url: "https://github.com/sudo-project/sudo/blob/v1.9.17p2/plugins/sudoers/display.c",
    },
    {
      claim:
        "sudo 1.9.17p2 source, plugins/sudoers/fmtsudoers.c: a tag such as NOPASSWD is printed as \"NOPASSWD: \" before the command, a flag Defaults entry is printed by its name (for example env_reset), and the command is printed with any arguments written in the rule",
      url: "https://github.com/sudo-project/sudo/blob/v1.9.17p2/plugins/sudoers/fmtsudoers.c",
    },
    {
      claim:
        "sudo 1.9.17p2 source, plugins/sudoers/sethost.c: the host name shown in the listing is the part of the host name before the first dot",
      url: "https://github.com/sudo-project/sudo/blob/v1.9.17p2/plugins/sudoers/sethost.c",
    },
    {
      claim: "sudo 1.9.17p2 is a tagged release of the sudo project (published 26 July 2025)",
      url: "https://github.com/sudo-project/sudo/releases/tag/v1.9.17p2",
    },
    {
      claim:
        "MITRE ATT&CK T1548.003 Sudo and Sudo Caching: adversaries may perform sudo caching and/or use the sudoers file to elevate privileges; sudo allows a system administrator to delegate authority to give certain users the ability to run some (or all) commands as root or another user; the sudoers file can specify when to not prompt users for passwords with a line like user1 ALL=(ALL) NOPASSWD: ALL; mitigation M1026: by requiring a password, even if an adversary can get terminal access, they must know the password to run anything in the sudoers file; mitigation M1022: the sudoers file should be strictly edited such that passwords are always required and that users can't spawn risky processes as users with higher privilege; tactic Privilege Escalation",
      url: "https://attack.mitre.org/techniques/T1548/003/",
    },
    {
      claim: "MITRE ATT&CK tactic TA0004 Privilege Escalation: the adversary is trying to gain higher-level permissions",
      url: "https://attack.mitre.org/tactics/TA0004/",
    },
    {
      claim:
        "GTFOBins home page: a curated list of Unix-like executables that can be used to bypass local security restrictions in misconfigured systems; it is not a list of exploits, and the programs listed are not vulnerable per se",
      url: "https://gtfobins.org/",
    },
    {
      claim:
        "GTFOBins vi: functions Shell (can spawn an interactive system shell), File write and File read, each with a Sudo context: the function is performed by the privileged user if executed via sudo because the acquired privileges are not dropped",
      url: "https://gtfobins.org/gtfobins/vi/",
    },
    {
      claim:
        "GTFOBins vim: functions include File read, with the same Sudo context (acquired privileges are not dropped), and inheritance from vi, thus possibly granting Shell, File write and File read",
      url: "https://gtfobins.org/gtfobins/vim/",
    },
    {
      claim:
        "GTFOBins less: functions Shell, Command, File write and File read, so a pager appears alongside editors among the programs the project lists",
      url: "https://gtfobins.org/gtfobins/less/",
    },
    {
      claim:
        "NIST SP 800-53 Rev. 5, AC-6 Least Privilege: employ the principle of least privilege, allowing only authorized accesses for users (or processes acting on behalf of users) that are necessary to accomplish assigned organizational tasks",
      url: "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf",
    },
    {
      claim:
        "NCSC, Secure system administration, Use privileged access management: Just enough Administration is another way of describing the concept of least privilege; over-zealous permissions are unnecessary and add risk to your systems",
      url: "https://www.ncsc.gov.uk/collection/secure-system-administration/use-privileged-access-management",
    },
  ],
};
