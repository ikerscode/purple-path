import scope from "./01-scope.js";
import recon from "./02-recon.js";

export default [scope, recon].sort((a, b) => a.order - b.order);
