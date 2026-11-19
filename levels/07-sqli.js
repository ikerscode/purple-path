const SOURCE_LINES = [
  "# catalogue.py - catalogue lookups for the Quillon Books site",
  "# (fictional exercise code). The title, author, max_price and isbn",
  "# values arrive from the search form as plain text.",
  "import sqlite3",
  "",
  'db = sqlite3.connect("catalogue.db")',
  "",
  "",
  "def find_by_title(title):",
  "    cur = db.cursor()",
  "    query = \"SELECT id, title, price FROM books WHERE title = '\" + title + \"'\"",
  "    cur.execute(query)",
  "    return cur.fetchall()",
  "",
  "",
  "def find_by_author(author):",
  "    cur = db.cursor()",
  '    query = "SELECT id, title, price FROM books WHERE author = ?"',
  "    cur.execute(query, (author,))",
  "    return cur.fetchall()",
  "",
  "",
  "def books_under(max_price):",
  "    cur = db.cursor()",
  '    query = "SELECT id, title FROM books WHERE price < " + max_price',
  "    cur.execute(query)",
  "    return cur.fetchall()",
  "",
  "",
  "def find_by_isbn(isbn):",
  "    cur = db.cursor()",
  '    cur.execute("SELECT id, title FROM books WHERE isbn = ?", (isbn,))',
  "    return cur.fetchall()",
];

const SOURCE = SOURCE_LINES.join("\n") + "\n";

// What `grep -n SELECT src/catalogue.py` prints: each matching line prefixed with its
// 1-based line number and a colon; no file name, because only one file is searched.
const GREP_SELECT = SOURCE_LINES.map((l, i) => [i + 1, l])
  .filter(([, l]) => l.includes("SELECT"))
  .map(([n, l]) => `${n}:${l}`)
  .join("\n");

const LINES_CONCAT = "Lines 11 and 25";
const LINES = [LINES_CONCAT, "Lines 18 and 32", "Lines 11 and 18", "Lines 25 and 32"];

const CATEGORY_RIGHT = "A03:2021 Injection";
const CATEGORIES = ["A01:2021 Broken Access Control", "A02:2021 Cryptographic Failures", CATEGORY_RIGHT, "A05:2021 Security Misconfiguration"];

const IMPACT_RIGHT =
  "Depending on database features and privileges, the stored data can be read or modified, database administration operations can be run, and in some cases operating system commands can be run";
const IMPACTS = [
  IMPACT_RIGHT,
  "Nothing, because a database driver always removes dangerous characters from a query before it runs",
  "Only the colours and fonts of the page change, because SQL has no effect on stored data",
  "The visitor's browser runs script taken from the page, which is what SQL injection means",
];

const DEFENCE_CORRECT =
  "Bind every user-supplied value through placeholders so the SQL text stays a fixed constant, and treat input validation and least-privilege database accounts as extra layers";

export default {
  id: "07-sqli",
  order: 7,
  tier: "intermediate",
  title: "Data is not code",
  term: "SQL injection",
  card: {
    what: "A SQL injection attack occurs when untrusted data (usually strings) becomes part of a query's SQL syntax, according to the OWASP SQL Injection Prevention Cheat Sheet. In the OWASP Top 10 2021 it falls under A03:2021 Injection (the 2025 edition lists Injection as A05:2025), and it is catalogued as CWE-89.",
    why: "OWASP says a successful attack can, depending on database features and privileges, read data from the database, modify it, and execute administration operations on the database, and in some cases execute operating system commands. OWASP's A03 page says source code review is the best method of detecting if applications are vulnerable to injections. Only review code you are authorised to review.",
    example: "A query built as \"... WHERE title = '\" + title + \"'\" joins the input into the SQL text. A query written as \"... WHERE title = ?\", with the value passed as a separate argument, does not.",
  },
  world: {
    hosts: [
      { ip: "198.51.100.60", hostname: "db.quillon.example", inScope: false, services: [] },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional shop, fictional code).\nYou are reviewing one source file exported from the shop's code. Nothing here connects to a live system.\nStart with brief.txt. Tools: cat and ls, plus one form of grep: grep -n SELECT src/catalogue.py\nType help for the built-ins.",
      "/home/analyst/brief.txt":
        "REVIEW BRIEF (fictional exercise document)\n\nClient:   Quillon Books Ltd (fictional)\nTask:     Read the exported catalogue code and say which lookups build their SQL safely and which do not.\n\nIN THE EXPORT\n  src/catalogue.py    the four catalogue lookups behind the shop's search form\n\nNOT PART OF THIS REVIEW\n  db.quillon.example (198.51.100.60), the live database server.\n  Work from the exported source file only.",
      "/home/analyst/src/catalogue.py": SOURCE,
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^grep -n (\"SELECT\"|'SELECT'|SELECT) (src/catalogue\\.py|/home/analyst/src/catalogue\\.py)$",
      caseSensitive: true,
      output: GREP_SELECT,
      event: "grep:select",
    },
  ],
  outOfScope: {
    hosts: ["198.51.100.60", "db.quillon.example"],
    message:
      "That command named the live database server, which your review brief lists as not part of this review. The brief says to work from the exported source file only. In this exercise the review ends as soon as that server's name or address is named.",
  },
  objectives: [
    {
      id: "read-brief",
      prompt: "Read the review brief first: cat brief.txt",
      check: { type: "event", value: "read:/home/analyst/brief.txt" },
      success: "The brief limits the review to one exported source file and lists the live database server as not part of the review. Work from the file only.",
    },
    {
      id: "read-source",
      prompt: "Read the catalogue code: cat src/catalogue.py",
      check: { type: "event", value: "read:/home/analyst/src/catalogue.py" },
      success: "Four lookups, each running one SELECT. Two of them join a variable onto the SQL text with +. The other two write a ? in the SQL text and pass the value as a separate argument.",
    },
    {
      id: "list-sql",
      prompt: "List every line that holds a SELECT, with line numbers: grep -n SELECT src/catalogue.py",
      check: { type: "event", value: "grep:select" },
      success: "grep -n puts each matching line's number and a colon in front of it, and leaves out the file name because only one file is searched. Compare how the four query strings end.",
    },
    {
      id: "concat-lines",
      prompt: "Which lines build SQL by concatenating input into the query text?",
      check: { type: "choice", value: LINES_CONCAT, options: LINES },
      success: "Lines 11 and 25. They join title and max_price onto the SQL text. CWE-89 describes the weakness: SQL is built from externally-influenced input, and without sufficient removal or quoting of SQL syntax the input can be interpreted as SQL instead of ordinary user data. Lines 18 and 32 keep the SQL text fixed and pass the value separately.",
    },
    {
      id: "category",
      prompt: "Which OWASP Top 10 2021 category covers this flaw?",
      check: { type: "choice", value: CATEGORY_RIGHT, options: CATEGORIES },
      success: "A03:2021 Injection. Its page lists CWE-89 (SQL Injection) among its notable CWEs, and says an application is vulnerable when, among other things, hostile data is directly used or concatenated, or when dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter.",
    },
    {
      id: "impact",
      prompt: "What can a successful SQL injection attack lead to, according to OWASP?",
      check: { type: "choice", value: IMPACT_RIGHT, options: IMPACTS },
      success: "OWASP's cheat sheet says the effects depend on database features and privileges: reading data, modifying data, running administration operations on the database, and in some cases running operating system commands. The other options are wrong: the flaw is in how the query is built, and a different flaw makes a visitor's browser run script.",
    },
    {
      id: "fix-name",
      prompt: "What is the primary defence for lines 11 and 25 called? Type its name (two words).",
      check: {
        type: "answer",
        value: [
          "parameterized queries",
          "parameterised queries",
          "parameterized query",
          "parameterised query",
          "prepared statements",
          "prepared statement",
        ],
      },
      success: "Parameterized queries, which PortSwigger says are also known as prepared statements. The OWASP cheat sheet lists them first among its preferred patterns: define the SQL structure separately from its data values and bind the values through the database API. Lines 18 and 32 already do this with Python's ? placeholders.",
    },
  ],
  defence: {
    prompt:
      "Quillon's developers can change this code. Which plan follows the guidance you have read?",
    check: {
      type: "choice",
      value: DEFENCE_CORRECT,
      options: [
        DEFENCE_CORRECT,
        "Escape the special characters in each value by hand and keep concatenating, with that as the main defence",
        "Validate each value and keep concatenating the ones that pass, because a validated value is safe to put into SQL text",
        "Put a web application firewall in front of the shop and leave the code unchanged, because the developers can rely on it to catch bad input",
      ],
    },
    explanation:
      "The OWASP SQL Injection Prevention Cheat Sheet lists parameterized queries first among its preferred patterns: define the SQL structure separately from its data values and bind those values through the database API. It warns that concatenating untrusted values into the query before preparing it defeats this protection, and PortSwigger adds that for a parameterized query to be effective the string used in the query must always be a hard-coded constant, never containing variable data from any origin. Parameter markers stand for data values, not table names, column names or keywords such as ASC and DESC, so for those parts the cheat sheet says to map the user's choice to a strict allow-list of fixed, application-owned values. Of manual escaping the cheat sheet says: do not manually escape untrusted values to construct SQL queries; it is error-prone, can fail and can allow SQL injections, and is strongly discouraged. It says input validation complements parameter binding but does not replace it, and that validation of a value does not make it safe to concatenate into SQL. The OWASP Top 10 2021 A03 page likewise says positive server-side input validation is not a complete defense, as many applications require special characters. CWE-89 says an application firewall can be beneficial when the code cannot be fixed, as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth, but that it might not cover all input vectors, that attack techniques might be available to bypass it, and that it might inadvertently reject or modify legitimate requests. Here the code can be fixed, so the firewall is not the fix. The cheat sheet's additional defenses, such as least privilege for database accounts, are for defense in depth, to limit damage if an injection does succeed.",
  },
  quiz: {
    question:
      "According to PortSwigger's Web Security Academy, what can parameterized queries not be used for?",
    options: [
      "Untrusted input in other parts of the query, such as table or column names or the ORDER BY clause",
      "Untrusted input that appears as data in the WHERE clause",
      "Values in an INSERT or UPDATE statement",
      "Queries in any language other than Java, because the technique is only available there",
    ],
    answer: 0,
    explanation:
      "PortSwigger says parameterized queries can be used wherever untrusted input appears as data within the query, including the WHERE clause and values in an INSERT or UPDATE statement, but they cannot handle untrusted input in other parts of the query, such as table or column names or the ORDER BY clause. Those parts need a different approach, such as whitelisting permitted input values or using different logic, and the OWASP cheat sheet likewise says to map such choices to a strict allow-list of fixed values. The technique is not tied to one language: the OWASP Query Parameterization Cheat Sheet shows prepared statements in Java, .NET, Ruby, PHP, Cold Fusion, Perl and Rust, and Python's sqlite3 documentation shows the ? placeholder.",
  },
  glossary: [
    {
      term: "SQL injection",
      definition:
        "The OWASP SQL Injection Prevention Cheat Sheet says it occurs when untrusted data (usually strings) becomes part of a query's SQL syntax, modifying the logic of the SQL request. PortSwigger describes it as a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It is catalogued as CWE-89.",
    },
    {
      term: "Parameterized query (prepared statement)",
      definition:
        "A query whose SQL structure is defined separately from its data values, with the values bound through the database API (OWASP). PortSwigger says these are also known as prepared statements. In Python's sqlite3 module the SQL text holds a ? placeholder and the values are passed as the second argument of execute().",
    },
    {
      term: "OWASP Top 10 2021: A03 Injection",
      definition:
        "The third category of the 2021 list. Its notable CWEs include CWE-79 (Cross-site Scripting) and CWE-89 (SQL Injection), and it says preventing injection requires keeping data separate from commands and queries.",
    },
    {
      term: "Defense in depth (hardening)",
      definition:
        "The OWASP cheat sheet recommends adopting additional defenses such as least privilege for database accounts and input validation to provide defense in depth, limiting the damage if an injection succeeds. Input validation complements parameter binding; it does not replace it.",
    },
  ],
  hints: [
    "Start with the brief, then read src/catalogue.py with cat. Each function runs one SELECT.",
    "grep -n SELECT src/catalogue.py shows the four query strings with their line numbers. Look at how each string ends: a + and a variable, or a ?.",
    "The two lines that join a variable onto the SQL text are the flawed ones. The fix is to keep the SQL text fixed and pass the value separately, which is the ? form already used on the other two lines.",
  ],
  solution: [
    "cat brief.txt",
    "cat src/catalogue.py",
    "grep -n SELECT src/catalogue.py",
    LINES_CONCAT,
    CATEGORY_RIGHT,
    IMPACT_RIGHT,
    "parameterized queries",
    DEFENCE_CORRECT,
  ],
  sources: [
    {
      claim: "OWASP Top 10 2021 A03 Injection, Overview: the category lists CWE-79 Cross-site Scripting and CWE-89 SQL Injection among its notable CWEs; Description: an application is vulnerable when dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter, and when hostile data is directly used or concatenated; source code review is the best method of detecting if applications are vulnerable to injections; How to Prevent: preventing injection requires keeping data separate from commands and queries, positive server-side input validation is not a complete defense as many applications require special characters, and SQL structures such as table and column names cannot be escaped",
      url: "https://top10.owasp.org/2021/A03_2021-Injection/index.html",
    },
    {
      claim: "OWASP Top 10 2021 list: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration",
      url: "https://top10.owasp.org/2021/",
    },
    {
      claim: "OWASP Top 10 2025 list: A05:2025 Injection (A03:2025 Software Supply Chain Failures, A04:2025 Cryptographic Failures)",
      url: "https://top10.owasp.org/2025/",
    },
    {
      claim: "OWASP SQL Injection Prevention Cheat Sheet, Introduction: an attack occurs when untrusted data (usually strings) becomes part of a query's SQL syntax; a successful attack can, depending on database features and privileges, read data, modify data, execute administration operations on the database, and in some cases execute operating system commands; Primary Defenses: parameterized queries are the preferred pattern, with the SQL structure defined separately from its data values and bound through the database API, and concatenating untrusted values into the query before preparing it defeats the protection; structural parts such as table names, column names and sort direction are mapped to a strict allow-list of fixed values; Manually escaping (STRONGLY DISCOURAGED): do not manually escape untrusted values to construct SQL queries; it is error-prone and can fail and allow SQL injections; Hardening: additional defenses such as least privilege provide defense in depth to limit damage, and input validation complements parameter binding but does not replace it",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    },
    {
      claim: "OWASP Query Parameterization Cheat Sheet, Parameterized Query Examples: SQL injection is best prevented through the use of parameterized queries, with prepared statement examples in Java, .NET, Ruby, PHP, Cold Fusion, Perl and Rust",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
    },
    {
      claim: "PortSwigger Web Security Academy, What is SQL injection (SQLi)? and How to prevent SQL injection: SQL injection is a vulnerability that allows an attacker to interfere with the queries an application makes to its database; most instances can be prevented using parameterized queries (also known as prepared statements) instead of string concatenation; they can be used wherever untrusted input appears as data in the query, including the WHERE clause and values in INSERT or UPDATE, but not for other parts such as table or column names or the ORDER BY clause, which need a different approach such as whitelisting permitted input values; for a parameterized query to be effective the string used in the query must always be a hard-coded constant",
      url: "https://portswigger.net/web-security/sql-injection",
    },
    {
      claim: "CWE-89 (version 5.0), Description: SQL is constructed using externally-influenced input without neutralizing special elements, so inputs can be interpreted as SQL instead of ordinary user data; Potential Mitigations: parameterization with prepared statements, Strategy Firewall (an application firewall can be beneficial when the code cannot be fixed, as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth, but might not cover all input vectors, attack techniques might be available to bypass it, and it might inadvertently reject or modify legitimate requests)",
      url: "https://cwe.mitre.org/data/definitions/89.html",
    },
    {
      claim: "Python documentation, sqlite3, How to use placeholders to bind values in SQL queries: beware of using Python's string operations to assemble queries, as they are vulnerable to SQL injection attacks; instead use a placeholder in the string and substitute the values by providing them as a tuple as the second argument of the cursor's execute() method; the qmark style uses question marks",
      url: "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders",
    },
    {
      claim: "GNU grep manual, section 2.1.4 Output Line Prefix Control: -n (--line-number) prefixes each line of output with the 1-based line number within its input file; -h is the default when there is only one file to search; section 2.1.5 Context Line Control: matching lines normally use a colon as the separator between prefix fields and line content",
      url: "https://www.gnu.org/software/grep/manual/grep.html",
    },
  ],
};
