const APP_PY =
  'from flask import Flask, render_template, request\n\napp = Flask(__name__)\n\n\n@app.route("/search")\ndef search():\n    q = request.args.get("q", "")\n    return render_template("search.html", q=q)\n';

const TEMPLATE_LINES = [
  "<!doctype html>",
  '<html lang="en">',
  "<head><title>Search - Fellside Outfitters</title></head>",
  "<body>",
  "<h1>Results for {{ q|safe }}</h1>",
  '<form action="/search" method="get">',
  '<input type="text" name="q" value="{{ q }}">',
  '<button type="submit">Search</button>',
  "</form>",
  "<script>",
  'var lastSearch = "{{ q }}";',
  "</script>",
  "</body>",
  "</html>",
];
const TEMPLATE = TEMPLATE_LINES.join("\n") + "\n";

// The page the template produces for the ordinary term "boots". Jinja removes a single trailing
// newline from the template, so the body has none. Nothing differs between an escaped and an
// unescaped placeholder for a term of plain letters, so all three places show the same text.
const BODY = TEMPLATE_LINES.join("\n").replace(/\{\{ q(\|safe)? \}\}/g, "boots");

const HEADERS = [
  "HTTP/1.1 200 OK",
  "Server: Werkzeug/3.1.9 Python/3.14.8",
  "Date: Thu, 19 Nov 2026 10:14:52 GMT",
  "Content-Type: text/html; charset=utf-8",
  `Content-Length: ${BODY.length}`,
  "Connection: close",
].join("\n");

const URL_RE = "[\"']?http://192\\.0\\.2\\.80:5000/search\\?q=boots[\"']?";

const CONTEXTS = ["HTML body (text between tags)", "HTML attribute value", "JavaScript string", "CSS value"];
const CTX_BODY = CONTEXTS[0];
const CTX_ATTR = CONTEXTS[1];
const CTX_JS = CONTEXTS[2];

const WHICH_HEADING = "The heading in the h1 element, because the |safe filter switches escaping off there";
const WHICH_BOX = "The value of the search box, because it sits inside an attribute";
const WHICH_SCRIPT = "The lastSearch variable in the script, because it sits inside quotes";
const WHICH_NONE = "None of them, because Flask escapes every placeholder in every template";
const WHICH = [WHICH_HEADING, WHICH_BOX, WHICH_SCRIPT, WHICH_NONE];

const WRONG_HEADING = "The heading in the h1 element";
const WRONG_BOX = "The value of the search box";
const WRONG_SCRIPT = "The lastSearch variable in the script";
const WRONG_NONE = "None of them, because HTML escaping is the right encoding in every context";
const WRONG = [WRONG_HEADING, WRONG_BOX, WRONG_SCRIPT, WRONG_NONE];

const CSP_NO = "No: no Content-Security-Policy header appears in the response headers";
const CSP = [
  "Yes: the response has a Content-Security-Policy header",
  CSP_NO,
  "Yes, but only as a meta element inside the page",
];

const T_REFLECTED = "Reflected XSS";
const T_STORED = "Stored XSS";
const T_DOM = "DOM-based XSS";
const TYPES = [T_REFLECTED, T_STORED, T_DOM, "SQL injection"];

const DEFENCE_CORRECT =
  "Encode the term for each context it is output in (HTML encoding in the page body and in the quoted attribute, and inside the script an encoder documented for both the JavaScript string and the enclosing script element), and add a Content-Security-Policy as an extra layer";

export default {
  id: "08-xss",
  order: 8,
  tier: "intermediate",
  title: "Encode for the context",
  term: "Cross-site scripting (XSS)",
  card: {
    what: "OWASP says XSS happens when an application puts untrusted data into a page in a way that lets the browser treat it as code. PortSwigger describes three main types: reflected XSS, where the malicious script comes from the current HTTP request; stored XSS, where it comes from the website's database; and DOM-based XSS, where the vulnerability exists in client-side code rather than server-side code.",
    why: "In the OWASP Top 10 2021, CWE-79 (Cross-site Scripting) is one of the CWEs mapped to A03:2021 Injection. OWASP says XSS attacks are serious and can lead to account impersonation, observing user behavior, loading external content, stealing sensitive data, and more. Only test pages you are authorised to test.",
    example: "A search page that shows \"Results for boots\" has copied the search term from the request into its response. Whether that is safe depends on how the term is encoded for the place in the page where it lands.",
  },
  world: {
    hosts: [
      { ip: "192.0.2.80", hostname: "staging.fellside.example", inScope: true, services: [] },
      { ip: "198.51.100.80", hostname: "www.fellside.example", inScope: false, services: [] },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional shop, fictional code).\nStart with brief.txt. Tools: cat and ls, plus curl for the staging copy of the search page.\ncurl is modelled for the staging address and the search term boots only; put the address in quotes, for example:\n  curl -i \"http://192.0.2.80:5000/search?q=boots\"\nType help for the built-ins.",
      "/home/analyst/brief.txt":
        "REVIEW BRIEF (fictional exercise document)\n\nClient:   Fellside Outfitters Ltd (fictional)\nTask:     Review how the staging copy of the search page puts the search term into its HTML.\n\nIN THE EXERCISE\n  webapp/app.py                     the page's route\n  webapp/templates/search.html      the page's template\n  192.0.2.80, port 5000             the staging copy of the page\n\nNOT PART OF THIS REVIEW\n  www.fellside.example (198.51.100.80), the live shop.\n  Use the staging copy only, and only the ordinary search term boots.",
      "/home/analyst/webapp/app.py": APP_PY,
      "/home/analyst/webapp/templates/search.html": TEMPLATE,
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: `^curl (-i|-si|-s -i|-i -s) ${URL_RE}$`,
      caseSensitive: true,
      output: `${HEADERS}\n\n${BODY}`,
      event: "http:search-headers",
    },
    {
      match: `^curl( -s)? ${URL_RE}$`,
      caseSensitive: true,
      output: BODY,
      event: "http:search",
    },
  ],
  outOfScope: {
    hosts: ["198.51.100.80", "www.fellside.example"],
    message:
      "That command named the live shop, which your brief lists as not part of this review. The brief allows the staging copy only. In this exercise the engagement ends as soon as that site's name or address is named.",
  },
  objectives: [
    {
      id: "read-brief",
      prompt: "Read the review brief first: cat brief.txt",
      check: { type: "event", value: "read:/home/analyst/brief.txt" },
      success: "The brief allows the staging copy and the ordinary search term boots, and lists the live shop as not part of the review.",
    },
    {
      id: "read-template",
      prompt: "Read the page's template: cat webapp/templates/search.html",
      check: { type: "event", value: "read:/home/analyst/webapp/templates/search.html" },
      success: "The template puts the search term q into three places: the heading, the value of the search box, and a JavaScript variable. Flask's documentation says it turns autoescaping on for templates ending in .html, and Jinja's documentation says the |safe filter marks a value as safe so it is not escaped.",
    },
    {
      id: "fetch-page",
      prompt: "Fetch the staging page with its headers: curl -i \"http://192.0.2.80:5000/search?q=boots\"",
      check: { type: "event", value: "http:search-headers" },
      success: "curl -i shows the response headers in the same output as the page. For a term made only of ordinary letters, the term appears the same way in all three places, so the response alone cannot show which placeholders are escaped. The template can.",
    },
    {
      id: "ctx-heading",
      prompt: "The term appears in the h1 heading. What output context is that?",
      check: { type: "choice", value: CTX_BODY, options: CONTEXTS },
      success: "HTML body: text between tags. PortSwigger calls this XSS between HTML tags, and OWASP calls it an HTML context. The encoding for it is HTML entity encoding.",
    },
    {
      id: "ctx-input",
      prompt: "The term appears in value=\"...\" on the search box. What output context is that?",
      check: { type: "choice", value: CTX_ATTR, options: CONTEXTS },
      success: "HTML attribute value. OWASP says to surround attribute values with quotation marks and to use HTML attribute encoding for ordinary text attributes such as value. This one is quoted, and the placeholder is escaped.",
    },
    {
      id: "ctx-script",
      prompt: "The term appears between quotes in the script element. What output context is that?",
      check: { type: "choice", value: CTX_JS, options: CONTEXTS },
      success: "A JavaScript string. PortSwigger lists XSS into JavaScript as its own context, and OWASP says browsers parse HTML, JS, URLs and CSS differently, so each needs its own encoding.",
    },
    {
      id: "which-unescaped",
      prompt: "Which placeholder has escaping switched off?",
      check: { type: "choice", value: WHICH_HEADING, options: WHICH },
      success: "The heading. {{ q|safe }} marks the value as safe, so Jinja does not escape it, while the other two placeholders use the default escaping. OWASP recommends the approach where a framework escapes every value it renders by default, because it does not depend on deciding correctly which data is untrusted.",
    },
    {
      id: "which-wrong-context",
      prompt: "Which placeholder is escaped, but with HTML escaping where a different context calls for a different encoding?",
      check: { type: "choice", value: WRONG_SCRIPT, options: WRONG },
      success: "The script variable. Autoescaping gives HTML escaping, and OWASP says using the wrong encoding method may introduce weaknesses or harm the functionality of the application. For a JavaScript string OWASP asks for an encoder documented for both the JavaScript string and the enclosing HTML script. The search box value is the placeholder where HTML attribute encoding is the right kind.",
    },
    {
      id: "csp-header",
      prompt: "Look at the headers from your curl -i output. Does the response carry a Content-Security-Policy header?",
      check: { type: "choice", value: CSP_NO, options: CSP },
      success: "No. The headers are Server, Date, Content-Type, Content-Length and Connection. MDN says a CSP should be delivered in the Content-Security-Policy response header, so this response sets no policy to act as a second layer, and the page's HTML has no meta element for one either.",
    },
    {
      id: "type-reflected",
      prompt: "This page copies the term from the request into the response it sends straight back. If that were done unsafely, which type of XSS would it be?",
      check: { type: "choice", value: T_REFLECTED, options: TYPES },
      success: "Reflected XSS: PortSwigger says it arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.",
    },
    {
      id: "type-stored",
      prompt: "Suppose the shop saved each search term and showed it to later visitors in their pages. If that were done unsafely, which type of XSS would it be?",
      check: { type: "choice", value: T_STORED, options: TYPES },
      success: "Stored XSS: PortSwigger says it arises when an application receives data from an untrusted source and includes that data within its later HTTP responses in an unsafe way.",
    },
    {
      id: "type-dom",
      prompt: "Suppose JavaScript already in the page read the term from the page's address and wrote it back into the page. If that were done unsafely, which type of XSS would it be?",
      check: { type: "choice", value: T_DOM, options: TYPES },
      success: "DOM-based XSS: PortSwigger says it arises when an application contains client-side JavaScript that processes data from an untrusted source in an unsafe way, usually by writing the data back to the DOM.",
    },
  ],
  defence: {
    prompt:
      "The team wants to fix the search page. Which plan follows the guidance you have read?",
    check: {
      type: "choice",
      value: DEFENCE_CORRECT,
      options: [
        DEFENCE_CORRECT,
        "Add a Content-Security-Policy header and leave the templates as they are, because a policy replaces output encoding",
        "HTML-encode the term once and use that value in every placeholder, because one encoding is correct in every context",
        "Reject search terms that contain certain words and leave the templates as they are",
      ],
    },
    explanation:
      "The OWASP XSS Prevention Cheat Sheet says that to prevent XSS every place where untrusted data is added to the page needs protection, and that coverage is what matters: an application that protects 99 places and misses one is still vulnerable. It recommends output encoding, starting with the framework's default, and says the appropriate protection depends on how the data is used: there are many encoding methods because browsers parse HTML, JS, URLs and CSS differently, and using the wrong method may introduce weaknesses or harm the functionality of the application. In an HTML context it says to use HTML entity encoding; for an attribute, to surround the value with quotation marks and use an attribute encoder; and for a JavaScript string inserted by a server template, to use an encoder documented for both the JavaScript string and the enclosing HTML script. Jinja's documentation says its tojson filter produces output that is safe to render in HTML documents and script tags, with an exception for double-quoted HTML attributes. For the Content-Security-Policy, OWASP says it is an allowlist that prevents content being loaded, that it is easy to make mistakes with the implementation so it should not be your primary defense mechanism, and that it should be used as an additional layer of defense. MDN says setting a CSP is not an alternative to sanitizing input, and that websites should sanitize input and set a CSP, providing defense in depth against XSS. MDN also says that when a CSP contains a default-src or script-src directive, inline JavaScript is not allowed to execute unless extra measures are taken, so a policy with either directive would stop this page's inline script running unless extra measures were taken, such as a nonce or a hash, or the script were moved to a separate file from a source the policy allows. OWASP says input validation can enforce expected formats but does not replace these protections, and PortSwigger says validation should generally use whitelists rather than blacklists, so rejecting a list of words is not the fix. OWASP says a web application firewall can provide an additional layer of defense but cannot reliably prevent all XSS attacks or fix vulnerable application code, and that it should not be relied on as a substitute for context-aware output encoding, safe DOM APIs or HTML sanitization. OWASP also says no single technique will solve XSS and that a right combination of defensive techniques is necessary.",
  },
  quiz: {
    question:
      "According to the OWASP XSS Prevention Cheat Sheet, how should a Content Security Policy be used against XSS?",
    options: [
      "As an additional layer of defense, not as the primary defense mechanism",
      "As the primary defense, so that output encoding is no longer needed",
      "As a way to HTML-encode every value in the page automatically",
      "As one blanket policy for a whole enterprise, rather than customised for each application",
    ],
    answer: 0,
    explanation:
      "OWASP lists Content Security Policy among its other controls, describing it as an allowlist that prevents content being loaded, easy to get wrong, so it should not be the primary defense mechanism and should be used as an additional layer of defense. It says CSP works best used as a defense-in-depth technique and customised for each individual application rather than deployed as a one-size-fits-all enterprise solution, and it says framework protections, output encoding and HTML sanitization provide the best protection and are recommended in all circumstances. A CSP restricts what the browser loads and runs; it does not encode the values in the page.",
  },
  glossary: [
    {
      term: "Cross-site scripting (XSS)",
      definition:
        "OWASP says XSS happens when an application puts untrusted data into a page in a way that lets the browser treat it as code. PortSwigger describes it as a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application. CWE-79 is mapped to A03:2021 Injection in the OWASP Top 10 2021.",
    },
    {
      term: "Reflected, stored and DOM-based XSS",
      definition:
        "PortSwigger's three main types. Reflected XSS: the data comes from the current HTTP request and is included in the immediate response in an unsafe way. Stored XSS: the application receives data from an untrusted source and includes it in its later HTTP responses in an unsafe way. DOM-based XSS: client-side JavaScript processes data from an untrusted source in an unsafe way, usually by writing it back to the DOM.",
    },
    {
      term: "Output context",
      definition:
        "Where in the response the untrusted data lands, such as between HTML tags, in an HTML attribute value or in JavaScript. PortSwigger defines the XSS context as the location within the response where attacker-controllable data appears, and OWASP says the appropriate protection depends on how the data is used.",
    },
    {
      term: "Output encoding",
      definition:
        "OWASP's recommended protection when data should be displayed exactly as typed: encode the data for the context it is output in, so that it is displayed as data and not run as code. OWASP says using the wrong encoding method may introduce weaknesses or harm the functionality of the application.",
    },
    {
      term: "Content Security Policy (CSP)",
      definition:
        "MDN: a feature that helps to prevent or minimize the risk of certain types of security threats, made of instructions from a website to a browser. It should be delivered in the Content-Security-Policy response header, its primary use is to control which resources, in particular JavaScript resources, a document is allowed to load, and it provides defense in depth against XSS. OWASP says it should not be the primary defense mechanism.",
    },
  ],
  hints: [
    "Start with the brief, then read webapp/templates/search.html with cat. Count the places the term q is used.",
    "Fetch the page with the command in the README, including the quotes around the address. For the contexts, ask what surrounds each placeholder: tags, an attribute's quotes, or a JavaScript string.",
    "For the headers question, read the lines above the blank line in the curl -i output. For the XSS types, ask where the data comes from and when it reaches the page.",
  ],
  solution: [
    "cat brief.txt",
    "cat webapp/templates/search.html",
    'curl -i "http://192.0.2.80:5000/search?q=boots"',
    CTX_BODY,
    CTX_ATTR,
    CTX_JS,
    WHICH_HEADING,
    WRONG_SCRIPT,
    CSP_NO,
    T_REFLECTED,
    T_STORED,
    T_DOM,
    DEFENCE_CORRECT,
  ],
  sources: [
    {
      claim: "OWASP XSS Prevention Cheat Sheet, Introduction: XSS attacks are serious and can lead to account impersonation, observing user behavior, loading external content, stealing sensitive data, and more; no single technique will solve XSS, so the right combination of defensive techniques is necessary; XSS Defense Philosophy: XSS happens when an application puts untrusted data into a page in a way that lets the browser treat it as code, every place where untrusted data is added needs protection (an application that protects 99 places and misses one is still vulnerable), many frameworks escape every value by default and OWASP recommends this approach, and input validation can enforce expected formats but does not replace these protections",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    },
    {
      claim: "OWASP XSS Prevention Cheat Sheet, Output Encoding and its HTML, HTML Attribute and JavaScript Contexts sections: there are many output encoding methods because browsers parse HTML, JS, URLs and CSS differently, and using the wrong method may introduce weaknesses or harm functionality; HTML contexts use HTML entity encoding; attribute values are always surrounded by quotation marks and use an attribute encoder; for a server template inserting string data into an inline script, use an encoder documented for both the JavaScript string and the enclosing HTML script",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    },
    {
      claim: "OWASP XSS Prevention Cheat Sheet, Other Controls and Web Application Firewalls: Content Security Policy is an allowlist that prevents content being loaded, easy to get wrong, so it should not be the primary defense mechanism and should be an additional layer of defense; framework protections, output encoding and HTML sanitization provide the best protection and are recommended in all circumstances; WAFs cannot reliably prevent all XSS attacks or fix vulnerable application code and are not a substitute for context-aware output encoding; Common Anti-patterns, Sole Reliance on Content-Security-Policy (CSP) Headers: CSP works best used as a defense-in-depth technique and customised for each application rather than one-size-fits-all",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    },
    {
      claim: "OWASP Top 10 2021 A03 Injection, List of Mapped CWEs: CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') is mapped to the category; its Overview names CWE-79 among the notable CWEs",
      url: "https://top10.owasp.org/2021/A03_2021-Injection/index.html",
    },
    {
      claim: "PortSwigger Web Security Academy, Cross-site scripting: XSS is a vulnerability that allows an attacker to compromise users' interactions with a vulnerable application; the three main types are reflected (the malicious script comes from the current HTTP request), stored (it comes from the website's database) and DOM-based (the vulnerability is in client-side code rather than server-side code), with reflected XSS arising when data in an HTTP request is included in the immediate response in an unsafe way, stored XSS when data from an untrusted source is included in later responses, and DOM-based XSS when client-side JavaScript processes untrusted data unsafely, usually by writing it back to the DOM",
      url: "https://portswigger.net/web-security/cross-site-scripting",
    },
    {
      claim: "PortSwigger Web Security Academy, Cross-site scripting contexts: the XSS context is the location within the response where attacker-controllable data appears, and the contexts include text between HTML tags, HTML tag attributes and JavaScript",
      url: "https://portswigger.net/web-security/cross-site-scripting/contexts",
    },
    {
      claim: "PortSwigger Web Security Academy, How to prevent XSS: encoding should be applied directly before user-controllable data is written to a page because the context determines the encoding needed; validation should generally employ whitelists rather than blacklists; Jinja and React escape dynamic content by default",
      url: "https://portswigger.net/web-security/cross-site-scripting/preventing",
    },
    {
      claim: "MDN, Content Security Policy (CSP) guide: CSP is delivered in the Content-Security-Policy response header; its primary use case is controlling which resources a document may load, mainly as a defense against XSS; setting a CSP is not an alternative to sanitizing input and websites should do both, providing defense in depth; with a default-src or script-src directive inline JavaScript will not execute unless extra measures are taken; inline script elements are allowed if protected by a nonce or a hash",
      url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
    },
    {
      claim: "Flask documentation, Templates, Jinja Setup: autoescaping is enabled for all templates ending in .html, .htm, .xml and .xhtml, and .svg, when using render_template()",
      url: "https://flask.palletsprojects.com/en/stable/templating/",
    },
    {
      claim: "Jinja documentation, Template Designer, HTML Escaping and the safe and tojson filters: with automatic escaping everything is escaped by default except values explicitly marked safe, such as with the |safe filter; the tojson filter's output is safe to render in HTML documents and script tags, except in double-quoted HTML attributes",
      url: "https://jinja.palletsprojects.com/en/stable/templates/",
    },
    {
      claim: "curl manual: -i (--show-headers, called --include before 8.10.0) shows the response headers in the same output as the data",
      url: "https://curl.se/docs/manpage.html",
    },
  ],
};
