const KIND_PLAIN = "Plaintext: the password itself";
const KIND_ENCRYPTED = "Encrypted: reversible by anyone who holds the key";
const KIND_HASH_ONLY = "Hash only: no salt or cost factor stored with it";
const KIND_SALTED_SLOW = "Salted, slow password hashing: salt and cost stored in the value";
const KINDS = [KIND_PLAIN, KIND_ENCRYPTED, KIND_HASH_ONLY, KIND_SALTED_SLOW];

const DEFENCE_CORRECT =
  "Store only a password hash made with a slow, purpose-built password hashing scheme such as Argon2id or PBKDF2, using a unique random salt for each password, and keep the salt and cost settings with the hash";

export default {
  id: "04-hashing",
  order: 4,
  tier: "beginner",
  title: "Hash it, salt it, slow it",
  term: "Hashing vs encryption (storing passwords)",
  card: {
    what: "Encryption is a two-way function, so the original plaintext can be retrieved from encrypted data. Hashing is one-way: OWASP says it is impossible to \"decrypt\" a hash and obtain the original plaintext value. OWASP adds that in almost all circumstances passwords should be securely hashed with a modern, adaptive algorithm rather than encrypted or stored in plaintext.",
    why: "Logging in only needs the system to validate the typed password, and OWASP says one-way hashing is the most appropriate approach for that. NIST SP 800-63B-4 section 3.1.1.2 says passwords SHALL be salted and hashed using a suitable password hashing scheme (one that takes a password, a salt and a cost factor). Stored values can carry a format prefix that names the scheme, such as $2b$ for bcrypt or $argon2id$ for Argon2id.",
    example: "A bare hex string carries no such prefix. Its length alone does not tell you which function made it, and it does not show whether a salt or cost factor was used. Only review real systems and password data you are authorised to review.",
  },
  world: {
    hosts: [
      { ip: "198.51.100.40", hostname: "db01.example.test", inScope: false, services: [] },
    ],
    files: {
      "/home/analyst/README.txt":
        "Training exercise (fictional web shop, fictional data).\nYou are reviewing how the shop stores passwords. Everything you need is in two exported files on this workstation; nothing here connects to a live system.\nStart with brief.txt. Tools: cat and ls, plus wc -l on the user export. Type help for the built-ins.",
      "/home/analyst/brief.txt":
        "REVIEW BRIEF (fictional exercise document)\n\nClient:   Shopfront Example Ltd (fictional)\nTask:     Read the exported settings and the exported user table, and say how each stored password value is protected.\n\nIN THE EXPORT\n  review/auth.conf    the application's authentication settings\n  review/users.csv    five rows from the user table (fictional accounts)\n\nNOT PART OF THIS REVIEW\n  db01.example.test (198.51.100.40), the live database server.\n  Work from the exported files only.",
      "/home/analyst/review/auth.conf":
        "# shopfront auth.conf (fictional application, exported copy)\n\n[password_storage]\ncurrent_scheme  = argon2id\nrehash_on_login = true\n\n[stored_value_kinds]\n# The column users.pw_store holds one of these kinds. An account keeps the\n# kind written by the login code of its day until the user next signs in.\nv1  no prefix; the text exactly as the user typed it\nv2  64 lowercase hex characters; one pass of a digest function with no key\n    and no salt; the function name was not recorded\nv3  prefix \"enc1:\" then base64 of nonce + ciphertext + tag;\n    AES-256-GCM, key file /etc/shopfront/enc.key\nv4  written by the vendor password library (library string, starts with $)\nv5  written by the vendor password library (library string, starts with $)\n",
      "/home/analyst/review/users.csv":
        "id,username,pw_store\n1,rcarter,Maple-Harbor-Quill-519\n2,mokafor,enc1:s5cJQ9DDmspsfwzuKD5oDrRhT2pT1UcuxKeCpo6l7npXGBqNTUU7g1ahqVG2Bu/R\n3,dpatel,4ccbfaeee918c8bccdf52c5e6f2e3314e188d2b42724af67a40471246b37f82e\n4,lnguyen,$2b$12$CnI4/r9e8/MIgy78Wr65X.wJ6OMvhE/jYrGJpLKHogYLNUAqtK/f2\n5,sbrown,\"$argon2id$v=19$m=19456,t=2,p=1$M80DflhvTxkhI20aLhpjhg$K9mvta3OpgjTmNYc8VhdX1AzBAj6mGwWN96O6V2dpwQ\"\n",
    },
    user: "analyst",
    cwd: "/home/analyst",
  },
  commands: [
    {
      match: "^wc -l review/users\\.csv$",
      output: "6 review/users.csv",
      event: "counted:users",
    },
    {
      match: "^wc -l /home/analyst/review/users\\.csv$",
      output: "6 /home/analyst/review/users.csv",
      event: "counted:users",
    },
  ],
  outOfScope: {
    hosts: ["198.51.100.40", "db01.example.test"],
    message:
      "That command named the live database server, which your review brief lists as not part of this review. The brief says to work from the exported files only. In this exercise the review ends as soon as that server's name or address is named.",
  },
  objectives: [
    {
      id: "read-config",
      prompt: "Read the application's exported settings: cat review/auth.conf",
      check: { type: "event", value: "read:/home/analyst/review/auth.conf" },
      success: "The settings say which kinds of stored value this application has written over time. Note which kinds mention a salt or a key.",
    },
    {
      id: "read-users",
      prompt: "Read the exported user table: cat review/users.csv",
      check: { type: "event", value: "read:/home/analyst/review/users.csv" },
      success: "Five accounts, five stored values. Match the shape of each value to the settings and to the card.",
    },
    {
      id: "kind-rcarter",
      prompt: "How is the stored value for rcarter protected?",
      check: { type: "choice", value: KIND_PLAIN, options: KINDS },
      success: "Plaintext. The value is the password itself, exactly as typed (kind v1 in auth.conf). OWASP says passwords should never be stored in plain text.",
    },
    {
      id: "kind-mokafor",
      prompt: "How is the stored value for mokafor protected?",
      check: { type: "choice", value: KIND_ENCRYPTED, options: KINDS },
      success: "Encrypted. The enc1: prefix marks the application's AES-256-GCM output (kind v3), and anyone who holds the key file can reverse it. OWASP says encryption is a two-way function, so the original plaintext can be retrieved.",
    },
    {
      id: "kind-dpatel",
      prompt: "How is the stored value for dpatel protected?",
      check: { type: "choice", value: KIND_HASH_ONLY, options: KINDS },
      success: "A hash, but only a hash. The settings say kind v2 used one pass of a digest function with no key and no salt, and the value shows no cost factor. The settings also say the function name was not recorded, and 64 hex characters on their own would not identify it.",
    },
    {
      id: "kind-lnguyen",
      prompt: "How is the stored value for lnguyen protected?",
      check: { type: "choice", value: KIND_SALTED_SLOW, options: KINDS },
      success: "A bcrypt-format string: the $2b$ prefix, then the cost (12 here), then the salt and hash in one string. The scheme, its cost and its salt all travel with the stored value.",
    },
    {
      id: "kind-sbrown",
      prompt: "How is the stored value for sbrown protected?",
      check: { type: "choice", value: KIND_SALTED_SLOW, options: KINDS },
      success: "An Argon2id string in the PHC format: the identifier argon2id, the version, the parameters m, t and p, then the salt and the hash. Everything needed to check a login again is in the one string.",
    },
    {
      id: "scheme-lnguyen",
      prompt: "Which scheme's documented prefix begins the value for lnguyen? Type its name.",
      check: { type: "answer", value: ["bcrypt"] },
      success: "bcrypt. The libxcrypt crypt(5) page lists \"$2b$\" as the bcrypt prefix.",
    },
    {
      id: "scheme-sbrown",
      prompt: "Which scheme's documented identifier begins the value for sbrown? Type its name.",
      check: { type: "answer", value: ["argon2id"] },
      success: "Argon2id. In the PHC string format the identifier for Argon2id is argon2id, so the string begins $argon2id$.",
    },
    {
      id: "count-weak",
      prompt: "Type a number: how many of the five stored values are not a salted, slow password hash?",
      check: { type: "answer", value: ["3", "three"] },
      success: "Three: the plaintext value, the encrypted value and the hash with no salt or cost factor. Only the bcrypt and Argon2id strings keep their salt and cost with the value.",
    },
  ],
  defence: {
    prompt:
      "The shop's login only ever needs to check a typed password, never to show it again. Which design for storing new passwords matches NIST SP 800-63B-4 and the OWASP Password Storage Cheat Sheet?",
    check: {
      type: "choice",
      value: DEFENCE_CORRECT,
      options: [
        DEFENCE_CORRECT,
        "Encrypt every password with a strong cipher and keep the key on the same server, so the original can be read back when needed",
        "Hash each password once with a fast general-purpose hash such as SHA-256 and no salt, so logins stay quick",
        "Store each password as typed and rely on restricting who can read the database table",
      ],
    },
    explanation:
      "NIST SP 800-63B-4 section 3.1.1.2 says verifiers SHALL store passwords in a form that is resistant to offline attacks, salted and hashed using a suitable password hashing scheme. The salt SHALL be at least 32 bits long and chosen to minimize salt value collisions among stored hashes, both the salt and the resulting hash SHALL be stored, and a reference to the scheme including the cost factor SHOULD be stored. The cost factor SHOULD be as high as practical without negatively impacting verifier performance. NIST adds that an approved scheme from the latest SP 800-132 (which approves PBKDF2) or updated NIST guidance SHOULD be used. OWASP says to use strong, slow hashing algorithms such as Argon2id, bcrypt or PBKDF2 with a unique salt for each password, and that fast algorithms such as SHA-256 are not suitable for password storage. OWASP's first recommendation is Argon2id (it says PBKDF2 should be the preferred algorithm where FIPS-140 compliance is required), and it says bcrypt should only be used in legacy systems where Argon2 and scrypt are not available. It lists several equivalent minimum Argon2id settings, one being m=19456 (19 MiB), t=2, p=1, and says the only difference between them is a trade-off between CPU and RAM use. OWASP says the only time encryption should be used for passwords is in edge cases where the original plaintext is needed, and that passwords should never be stored in plain text. For accounts that still hold older values, OWASP describes re-hashing a password with the new algorithm when the user next authenticates.",
  },
  quiz: {
    question:
      "According to the OWASP Password Storage Cheat Sheet, why is hashing the most appropriate approach for password validation?",
    options: [
      "Hashing is a one-way function, so there is no way to \"decrypt\" a hash and obtain the original plaintext value",
      "Hashing is a two-way function, so the application can decrypt the hash with its key whenever it needs the password",
      "Hashing stores the password unchanged and only controls who is allowed to read it",
      "Hashing and encryption are the same operation, so either one works equally well for passwords",
    ],
    answer: 0,
    explanation:
      "OWASP says hashing is a one-way function: it is impossible to \"decrypt\" a hash and obtain the original plaintext value, which is why it is the most appropriate approach for password validation. Encryption is the two-way function, so the original plaintext can be retrieved from encrypted data. A hash is a computed value rather than the password itself, and hashing and encryption are different operations, which is why OWASP says passwords should in almost all circumstances be hashed rather than encrypted.",
  },
  glossary: [
    {
      term: "Hashing",
      definition:
        "A one-way function. OWASP says it is impossible to \"decrypt\" a hash and obtain the original plaintext value. The NIST SP 800-63B-4 glossary defines a hash function as a function that maps a bit string of arbitrary length to a fixed-length bit string.",
    },
    {
      term: "Encryption",
      definition:
        "A two-way function: OWASP says the original plaintext can be retrieved from encrypted data. OWASP says the only time encryption should be used for passwords is in edge cases where the original plaintext is needed, for example to authenticate to another system that does not support a modern way to grant access programmatically, and that an alternative architecture should be used wherever possible.",
    },
    {
      term: "Salt",
      definition:
        "The NIST SP 800-63B-4 glossary defines a salt as a non-secret value used in a cryptographic process, usually to ensure that the results of computations for one instance cannot be reused by an attacker. For passwords, OWASP describes a unique random string added to each password as part of the hashing process, and NIST says the salt and the resulting hash are both stored.",
    },
    {
      term: "Password hashing scheme and cost factor",
      definition:
        "NIST SP 800-63B-4 section 3.1.1.2: a password hashing scheme takes a password, a salt and a cost factor as inputs and generates a password hash, and its purpose is to make each password guess more expensive for an attacker who has obtained a hashed password file. OWASP calls the cost the work factor and says it is typically stored in the hash output.",
    },
    {
      term: "Format prefix (crypt and PHC strings)",
      definition:
        "The libxcrypt crypt(5) page says a hashed passphrase consists of a prefix, options, a salt and a hash, and that the prefix controls which hashing method is used; its prefix for bcrypt is \"$2b$\". The PHC string format begins $<id>$ and its identifier for Argon2id is argon2id, with the parameters m, t and p in that order.",
    },
    {
      term: "Argon2id",
      definition:
        "OWASP says Argon2 won the 2015 Password Hashing Competition and that of the three Argon2 variants the Argon2id variant should be used, because it provides a balanced approach to resisting both side-channel and GPU-based attacks. RFC 9106 calls Argon2id the primary variant of Argon2.",
    },
    {
      term: "bcrypt",
      definition:
        "A password hashing function. OWASP says it should only be used for password storage in legacy systems where Argon2 and scrypt are not available, with a work factor as large as verification server performance allows and a minimum of 10.",
    },
  ],
  hints: [
    "Start with the brief if you like, then read the two files in review/ with cat. The settings explain the application's own formats.",
    "Look at the start of each stored value. Readable text, a documented prefix, bare hex, or a string beginning with $ each point to a different kind. The card lists two $ prefixes.",
    "A bare hex string does not name its function, and the settings say no salt or key was used for that kind. For the count, add up the values that are not salted, slow hashes.",
  ],
  solution: [
    "cat review/auth.conf",
    "cat review/users.csv",
    KIND_PLAIN,
    KIND_ENCRYPTED,
    KIND_HASH_ONLY,
    KIND_SALTED_SLOW,
    KIND_SALTED_SLOW,
    "bcrypt",
    "argon2id",
    "3",
    DEFENCE_CORRECT,
  ],
  sources: [
    {
      claim: "NIST SP 800-63B-4 section 3.1.1.2 (Password Verifiers): verifiers SHALL store passwords in a form resistant to offline attacks; passwords SHALL be salted and hashed using a suitable password hashing scheme, which takes a password, a salt and a cost factor and generates a password hash, to make each guess more expensive for an attacker who has obtained a hashed password file; the cost factor SHOULD be as high as practical without negatively impacting verifier performance; the salt SHALL be at least 32 bits and chosen to minimize salt value collisions among stored hashes; both salt and hash SHALL be stored; a reference to the scheme including the cost factor SHOULD be stored; an approved password hashing scheme published in the latest revision of SP 800-132 or updated NIST guidelines on password hashing schemes SHOULD be used",
      url: "https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver",
    },
    {
      claim: "NIST SP 800-63B-4 glossary: salt is a non-secret value used in a cryptographic process, usually to ensure that the results of computations for one instance cannot be reused by an attacker; a hash function maps a bit string of arbitrary length to a fixed-length bit string",
      url: "https://pages.nist.gov/800-63-4/sp800-63b.html",
    },
    {
      claim: "NIST CSRC: SP 800-63B-4 was published July 2025 and supersedes SP 800-63B (March 2020)",
      url: "https://csrc.nist.gov/pubs/sp/800/63/b/4/final",
    },
    {
      claim: "OWASP Password Storage Cheat Sheet, Introduction and Hashing vs Encryption: in almost all circumstances passwords should be securely hashed with modern, adaptive algorithms rather than encrypted or stored in plaintext; hashing is one-way (impossible to decrypt a hash and obtain the original plaintext); encryption is two-way; encryption only in edge cases where the original plaintext is needed, with an alternative architecture preferred; passwords should never be stored in plain text",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    },
    {
      claim: "OWASP Password Storage Cheat Sheet, Introduction, Salting, Using Work Factors and Upgrading Legacy Hashes: a salt is a unique, random string added to each password (the sheet says unique, randomly generated); the work factor is typically stored in the hash output; fast algorithms such as SHA-256 are not suitable for password storage; re-hash with the new algorithm when the user next authenticates",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    },
    {
      claim: "OWASP Password Storage Cheat Sheet, Argon2id, bcrypt and PBKDF2:Argon2 won the 2015 Password Hashing Competition and the Argon2id variant should be used; equivalent minimum settings include m=19456 (19 MiB), t=2, p=1, the only difference being a trade-off between CPU and RAM use; bcrypt only for legacy systems where Argon2 and scrypt are not available, work factor minimum of 10; PBKDF2 should be preferred when FIPS-140 validated implementations are required",
      url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    },
    {
      claim: "libxcrypt crypt(5): a hashed passphrase consists of prefix, options, salt and hash, and the prefix controls which hashing method is used; bcrypt uses the prefix \"$2b$\" and the format \\$2[abxy]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}, with a 128-bit salt and a logarithmic CPU time cost parameter of 4 to 31",
      url: "https://manpages.debian.org/bookworm/libcrypt-dev/crypt.5.en.html",
    },
    {
      claim: "OpenBSD crypt(3): in a Blowfish (bcrypt) password string the version number, the logarithm of the number of rounds, and the concatenation of salt and hashed password are separated by the $ character",
      url: "https://man.openbsd.org/crypt.3",
    },
    {
      claim: "PHC string format: strings begin $<id>; the Argon2id identifier is argon2id; versions 16 and 19; parameters m (memory in kilobytes), t (iterations) and p (parallelism) in that order; the salt and hash are B64-encoded (default salt 16 bytes, 22 characters; default hash output 32 bytes, 43 characters)",
      url: "https://github.com/C2SP/C2SP/blob/main/phc-strings.md",
    },
    {
      claim: "RFC 9106: Argon2 has one primary variant, Argon2id; the version number v is one byte 0x13 (decimal 19); a 16-byte salt is recommended for password hashing and the salt should be unique for each password",
      url: "https://www.rfc-editor.org/rfc/rfc9106",
    },
    {
      claim: "NIST SP 800-38D section 7.1: the GCM authenticated encryption function takes an initialization vector, plaintext and additional authenticated data and outputs ciphertext and an authentication tag",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf",
    },
    {
      claim: "RFC 4180 section 2 item 6: fields containing line breaks, double quotes and commas should be enclosed in double quotes (the Argon2id value in the export contains commas)",
      url: "https://www.rfc-editor.org/rfc/rfc4180",
    },
    {
      claim: "NIST SP 800-132 approves PBKDF2 as the password-based key derivation function",
      url: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf",
    },
    {
      claim: "FIPS 180-4 Figure 1: SHA-256 and SHA-512/256 both produce 256-bit message digests",
      url: "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf",
    },
    {
      claim: "FIPS 202 section 1: SHA3-256 produces 256-bit digests, and the SHA-2 functions offer the same set of digest lengths, so a digest length alone does not identify the function",
      url: "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
    },
  ],
};
