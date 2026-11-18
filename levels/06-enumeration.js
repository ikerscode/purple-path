const ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/";

const BACKUP_LISTING =
  "<html>\n<head><title>Index of /backup/</title></head>\n<body>\n<h1>Index of /backup/</h1><hr><pre><a href=\"../\">../</a>\n<a href=\"README.txt\">README.txt</a>                                         10-Feb-2026 09:15                  33\n<a href=\"site-2026-02.sql.gz\">site-2026-02.sql.gz</a>                                28-Feb-2026 02:00               48213\n<a href=\"site-2026-03.sql.gz\">site-2026-03.sql.gz</a>                                01-Mar-2026 02:00               51377\n</pre><hr></body>\n</html>";

const INDEX_PAGE =
  "<!doctype html>\n<html><head><title>Larkfield Example Ltd</title></head>\n<body><h1>Larkfield Example Ltd</h1><p>Garden furniture since 1987.</p></body></html>";

const HEADERS_ROOT =
  "HTTP/1.1 200 OK\nServer: nginx/1.30.4\nDate: Thu, 13 Aug 2026 15:02:11 GMT\nContent-Type: text/html\nContent-Length: 158\nLast-Modified: Tue, 10 Feb 2026 09:15:00 GMT\nConnection: keep-alive\nETag: \"698af714-9e\"\nAccept-Ranges: bytes";

const BODY_401 =
  "<html>\n<head><title>401 Authorization Required</title></head>\n<body>\n<center><h1>401 Authorization Required</h1></center>\n<hr><center>nginx/1.30.4</center>\n</body>\n</html>";

const BODY_301 =
  "<html>\n<head><title>301 Moved Permanently</title></head>\n<body>\n<center><h1>301 Moved Permanently</h1></center>\n<hr><center>nginx/1.30.4</center>\n</body>\n</html>";

const gobuster = (wordlist) =>
  `===============================================================\nGobuster v3.8.2\nby OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n===============================================================\n[+] Url:                     http://192.0.2.50\n[+] Method:                  GET\n[+] Threads:                 10\n[+] Wordlist:                ${wordlist}\n[+] Negative Status codes:   404\n[+] User Agent:              gobuster/3.8.2\n[+] Timeout:                 10s\n===============================================================\nStarting gobuster in directory enumeration mode\n===============================================================\nadmin                (Status: 401) [Size: 179]\nbackup               (Status: 301) [Size: 169] [--> http://192.0.2.50/backup/]\nimages               (Status: 301) [Size: 169] [--> http://192.0.2.50/images/]\nrobots.txt           (Status: 200) [Size: 51]\nindex.html           (Status: 200) [Size: 158]\n===============================================================\nFinished\n===============================================================`;

export default {
  id: "06-enumeration",
  order: 6,
  tier: "intermediate",
  title: "Map the surface",
  term: "Enumeration",
  card: {
    what: "Enumeration here means listing what a web host exposes. The OWASP Web Security Testing Guide describes directory and file enumeration, such as requesting /admin, to find administrator interfaces that are not visibly linked. MITRE ATT&CK describes wordlist scanning as iteratively probing infrastructure with brute-forcing and crawling techniques, using wordlists of commonly used names.",
    why: "OWASP's guide says unreferenced and backup files may disclose sensitive information, and that a robots.txt file can be a source of clues about unreferenced directories. RFC 9309 says the rules in robots.txt are not a form of access authorization. Only enumerate systems you have written authorisation to test.",
    example: "A robots.txt that asks crawlers to stay out of /backup/ also tells every reader of the file that the path exists.",
  },
  world: {
    hosts: [
      {
        ip: "192.0.2.50",
        hostname: "www.larkfield.example",
        inScope: true,
        services: [{ port: 80, proto: "tcp", state: "open", service: "http", version: "nginx 1.30.4" }],
      },
      {
        ip: "192.0.2.51",
        hostname: "staff.larkfield.example",
        inScope: false,
        services: [],
      },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional client, fictional hosts).\nStart with the written authorisation in engagement/scope.txt.\nTools: cat, ls, curl and gobuster, run as an ordinary user.\ncurl is modelled for URLs on 192.0.2.50 (use the IP address), for example: curl http://192.0.2.50/robots.txt and curl -I http://192.0.2.50/\ngobuster is modelled for one form only: gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress\n(--no-progress turns off the live progress line, which redraws the terminal line.)",
      "/home/analyst/engagement/scope.txt":
        "ENGAGEMENT AUTHORISATION (fictional exercise document)\n\nClient:    Larkfield Example Ltd (fictional)\nTester:    A. Analyst\nSigned:    client IT director (fictional)\n\nAUTHORISED TARGETS\n  192.0.2.50    www.larkfield.example    public website\n\nEXCLUSION LIST (not authorised)\n  192.0.2.51    staff.larkfield.example\n                hosted by a third party, which has not agreed to testing\n\nPERMITTED TESTING\n  Reading robots.txt and public pages of the authorised target with curl.\n  One directory and file check of the authorised target with gobuster,\n  using the supplied wordlist wordlists/small.txt only.\n\nNOT PERMITTED\n  Opening or downloading the files that a directory listing shows.\n  Logging in to anything.\n  Any activity against a host that is not listed under AUTHORISED TARGETS.\n\nPOINT OF CONTACT\n  security@example.test - ask before doing anything this document does not cover.",
      "/home/analyst/wordlists/small.txt":
        "admin\nbackup\nimages\ncss\njs\nlogin\nuploads\nconfig\nold\ntest\napi\nstatic\nassets\nprivate\ntmp\ndev\nstaging\ndocs\ncgi-bin\nindex.html\nrobots.txt",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^curl( -s)? http://192\\.0\\.2\\.50/robots\\.txt$",
      output: ROBOTS,
      event: "http:robots",
    },
    {
      match: "^curl( -s)? http://192\\.0\\.2\\.50/backup/$",
      output: BACKUP_LISTING,
      event: "http:backup",
    },
    {
      match: "^curl( -s)? http://192\\.0\\.2\\.50/backup$",
      output: BODY_301,
    },
    {
      match: "^curl( -s)? http://192\\.0\\.2\\.50/?$",
      output: INDEX_PAGE,
    },
    {
      match: "^curl( -s)? http://192\\.0\\.2\\.50/admin/?$",
      output: BODY_401,
    },
    {
      match: "^curl (-I|-sI|-s -I|-I -s) http://192\\.0\\.2\\.50/?$",
      caseSensitive: true,
      output: HEADERS_ROOT,
      event: "http:headers",
    },
    {
      match: "^gobuster dir(?=.* -u http://192\\.0\\.2\\.50( |$))(?=.* -w wordlists/small\\.txt( |$))(?=.* --no-progress( |$))( -u \\S+| -w \\S+| --no-progress){3}$",
      output: gobuster("wordlists/small.txt"),
      event: "enum:gobuster",
    },
    {
      match: "^gobuster dir(?=.* -u http://192\\.0\\.2\\.50( |$))(?=.* -w /home/analyst/wordlists/small\\.txt( |$))(?=.* --no-progress( |$))( -u \\S+| -w \\S+| --no-progress){3}$",
      output: gobuster("/home/analyst/wordlists/small.txt"),
      event: "enum:gobuster",
    },
  ],
  outOfScope: {
    hosts: ["192.0.2.51", "staff.larkfield.example"],
    message:
      "You targeted a host on the exclusion list in your written authorisation, so you had no permission to test it. It is hosted by a third party that has not agreed to testing. Testing it would first need a change to the written scope. In this exercise the engagement ends here.",
  },
  objectives: [
    {
      id: "read-scope",
      prompt: "Read the written authorisation first: cat engagement/scope.txt",
      check: { type: "event", value: "read:/home/analyst/engagement/scope.txt" },
      success: "The scope allows curl on public pages and one gobuster run with the supplied wordlist. It does not allow opening the files a directory listing shows.",
    },
    {
      id: "read-robots",
      prompt: "Fetch the site's robots.txt: curl http://192.0.2.50/robots.txt",
      check: { type: "event", value: "http:robots" },
      success: "robots.txt asks crawlers to stay out of /admin/ and /backup/. RFC 9309 says listing paths in robots.txt exposes them publicly and makes them discoverable, and OWASP's guide notes that robots.txt can give clues about unreferenced directories.",
    },
    {
      id: "run-gobuster",
      prompt: "Check the site against the supplied wordlist: gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress",
      check: { type: "event", value: "enum:gobuster" },
      success: "gobuster requested each word in the wordlist as a path and listed those that did not return 404, the default negative status code. This is what the ATT&CK wordlist scanning technique describes: probing with commonly used names to identify content.",
    },
    {
      id: "status-401",
      prompt: "gobuster reported a status for admin. Type that status code.",
      check: { type: "answer", value: ["401"] },
      success: "RFC 9110 section 15.5.2: 401 indicates the request has not been applied because it lacks valid authentication credentials for the target resource. The area is protected by a login, but anyone can see that it exists.",
    },
    {
      id: "read-headers",
      prompt: "Fetch only the response headers of the home page: curl -I http://192.0.2.50/",
      check: { type: "event", value: "http:headers" },
      success: "curl -I fetches the headers only, using the HTTP HEAD request. OWASP's guide describes examining a response header as banner grabbing for web server fingerprinting.",
    },
    {
      id: "server-version",
      prompt: "Type the web server software and version that the Server header gives.",
      check: { type: "answer", value: ["nginx/1.30.4"] },
      success: "The Server header names the software and version. OWASP's guide says exposed server information is not necessarily a vulnerability in itself, but it can assist attackers and can lead them to version-specific server vulnerabilities.",
    },
    {
      id: "read-backup",
      prompt: "robots.txt named /backup/. Request it to see what the server returns: curl http://192.0.2.50/backup/",
      check: { type: "event", value: "http:backup" },
      success: "The server returns a directory listing: an Index of /backup/ page that names two database dump archives and a README. Stop here, since the scope does not permit opening those files. In nginx the autoindex directive controls whether a listing like this is produced, and its default is off.",
    },
  ],
  defence: {
    prompt:
      "Write the recommendations for the client. Which set follows the guidance you have read?",
    check: {
      type: "choice",
      value:
        "Move the backup files out of the web root, turn directory listing off, and stop the server advertising its version",
      options: [
        "Add more paths to robots.txt so that crawlers stay away from them",
        "Leave everything as it is, because exposed server information cannot help an attacker",
        "Move the backup files out of the web root, turn directory listing off, and stop the server advertising its version",
        "Remove the Disallow lines from robots.txt and leave the backup files where they are",
      ],
    },
    explanation:
      "OWASP's guide (WSTG-CONF-04) says data, log and configuration files should be stored in directories that the web server cannot reach, and OWASP Top 10 2021 A05 lists a directory listing that is not disabled on the server as a misconfiguration scenario. In nginx the autoindex directive is off by default, and server_tokens off stops nginx emitting its version on error pages and in the Server header. WSTG-INFO-02 says exposed server information is not necessarily in itself a vulnerability but can assist attackers, and recommends obscuring web server information in headers. RFC 9309 section 3 says the Robots Exclusion Protocol is not a substitute for valid content security measures and that listing paths in robots.txt makes them discoverable, so adding paths to it does not protect them. Removing the Disallow lines only removes a clue: the wordlist check found /backup without using robots.txt, and the listing is still served.",
  },
  quiz: {
    question: "What does RFC 9309 say about the rules in a robots.txt file?",
    options: [
      "They are enforced by the web server, which refuses requests for the listed paths",
      "They hide the listed paths from everyone except crawlers",
      "They are requests that crawlers are asked to honour, and are not a form of access authorization",
      "They replace the need for HTTP authentication on the listed paths",
    ],
    answer: 2,
    explanation:
      "RFC 9309 says the rules are ones that crawlers are requested to honor, and that they are not a form of access authorization. Section 3 says the protocol is not a substitute for valid content security measures, that listing paths exposes them publicly, and that to control access to the paths users should employ a valid security measure at the application layer, for example HTTP Authentication in the case of HTTP.",
  },
  glossary: [
    {
      term: "Enumeration",
      definition:
        "Listing what a target exposes, such as hidden paths and service details. OWASP's Web Security Testing Guide describes directory and file enumeration, for example requesting /admin, to find administrator interfaces that are not visibly linked.",
    },
    {
      term: "Wordlist scanning",
      definition:
        "MITRE ATT&CK T1595.003: iteratively probing infrastructure with brute-forcing and crawling techniques. Its goal is identifying content and infrastructure rather than discovering valid credentials, and the wordlists may hold generic, commonly used names and file extensions.",
    },
    {
      term: "robots.txt",
      definition:
        "A file of rules that crawlers are requested to honor when accessing URIs (RFC 9309). The rules are not a form of access authorization, and listing paths in the file makes them discoverable.",
    },
    {
      term: "HTTP status codes 301, 401 and 403",
      definition:
        "RFC 9110: 301 (Moved Permanently) says the target resource has been assigned a new permanent URI; 401 (Unauthorized) says the request lacks valid authentication credentials for the target resource; 403 (Forbidden) says the server understood the request but refuses to fulfil it.",
    },
    {
      term: "Banner grabbing",
      definition:
        "OWASP WSTG-INFO-02: sending an HTTP request to a web server and examining its response header, as one technique for fingerprinting the web server.",
    },
  ],
  hints: [
    "Start by reading the written authorisation: cat engagement/scope.txt. Use the IP address 192.0.2.50 in URLs.",
    "Run the check exactly as the README shows: gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress",
    "For the headers use curl -I http://192.0.2.50/ and read the Server line. Do not name the excluded host.",
  ],
  solution: [
    "cat engagement/scope.txt",
    "curl http://192.0.2.50/robots.txt",
    "gobuster dir -u http://192.0.2.50 -w wordlists/small.txt --no-progress",
    "401",
    "curl -I http://192.0.2.50/",
    "nginx/1.30.4",
    "curl http://192.0.2.50/backup/",
    "Move the backup files out of the web root, turn directory listing off, and stop the server advertising its version",
  ],
  sources: [
    {
      claim: "WSTG-INFO-03: robots.txt is in the web root; crawlers can intentionally ignore Disallow directives, so robots.txt should not be considered a mechanism to enforce restrictions on how web content is accessed",
      url: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage/",
    },
    {
      claim: "WSTG-CONF-04: unreferenced and backup files may disclose sensitive information; robots.txt is another source of clues about unreferenced directories; data, log and configuration files should be stored in directories not accessible by the web server",
      url: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information/",
    },
    {
      claim: "WSTG-CONF-05: directory and file enumeration, such as requesting /admin or /administrator, can reveal administrator interfaces that are not visibly available; hardening means admin pages are not accessible to everyone",
      url: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces/",
    },
    {
      claim: "WSTG-INFO-02: a banner grab sends an HTTP request and examines the response header; exposed server information is not necessarily in itself a vulnerability but can assist attackers and lead them to version-specific vulnerabilities; remediation includes obscuring web server information in headers",
      url: "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server/",
    },
    {
      claim: "OWASP Top 10 2021 A05 Security Misconfiguration: an example attack scenario is directory listing not being disabled on the server; recommends a minimal platform without unnecessary features",
      url: "https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/index.html",
    },
    {
      claim: "MITRE ATT&CK T1595.003 Wordlist Scanning: adversaries iteratively probe infrastructure using brute-forcing and crawling techniques to identify content and infrastructure rather than valid credentials, with wordlists of generic, commonly used names and file extensions or terms specific to particular software; web content discovery tools such as Dirb, DirBuster, and GoBuster are given as examples",
      url: "https://attack.mitre.org/techniques/T1595/003/",
    },
    {
      claim: "RFC 9309: robots.txt rules are ones crawlers are requested to honor and are not a form of access authorization (section 1); the protocol is not a substitute for valid content security measures, listing paths exposes them publicly and makes them discoverable, and access control should use a valid security measure such as HTTP Authentication (section 3)",
      url: "https://www.rfc-editor.org/rfc/rfc9309",
    },
    {
      claim: "RFC 9110: 301 Moved Permanently (15.4.2), 401 Unauthorized means the request lacks valid authentication credentials for the target resource (15.5.2), 403 Forbidden means the server understood the request but refuses to fulfil it (15.5.4)",
      url: "https://www.rfc-editor.org/rfc/rfc9110",
    },
    {
      claim: "gobuster v3.8.2 README: gobuster is a brute-forcing tool with a directory/file mode used as gobuster dir -u <url> -w <wordlist>",
      url: "https://github.com/OJ/gobuster/blob/v3.8.2/README.md",
    },
    {
      claim: "gobuster v3.8.2 source (gobusterdir/result.go): each result line is the path followed by '(Status: N)', '[Size: N]' and, when the response has a Location header, '[--> location]'",
      url: "https://github.com/OJ/gobuster/blob/v3.8.2/gobusterdir/result.go",
    },
    {
      claim: "gobuster v3.8.2 source (cli/dir/dir.go): the dir mode's negative status codes (status-codes-blacklist, -b) default to 404",
      url: "https://github.com/OJ/gobuster/blob/v3.8.2/cli/dir/dir.go",
    },
    {
      claim: "curl manual: -I (--head) fetches the headers only, using the HTTP HEAD command; -s (--silent) hides the progress meter",
      url: "https://curl.se/docs/manpage.html",
    },
    {
      claim: "nginx documentation: autoindex produces a directory listing and defaults to off (ngx_http_autoindex_module)",
      url: "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html",
    },
    {
      claim: "nginx changelog: nginx 1.30.4 was released on 15 July 2026",
      url: "https://nginx.org/en/CHANGES-1.30",
    },
    {
      claim: "nginx documentation: server_tokens on | off | build | string enables or disables emitting the nginx version on error pages and in the Server response header field",
      url: "https://nginx.org/en/docs/http/ngx_http_core_module.html",
    },
  ],
};
