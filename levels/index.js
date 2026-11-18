import scope from "./01-scope.js";
import recon from "./02-recon.js";
import ports from "./03-ports.js";
import hashing from "./04-hashing.js";
import phishing from "./05-phishing.js";
import enumeration from "./06-enumeration.js";

export default [scope, recon, ports, hashing, phishing, enumeration].sort((a, b) => a.order - b.order);
