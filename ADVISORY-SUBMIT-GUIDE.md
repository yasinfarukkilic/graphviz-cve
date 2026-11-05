# Advisory Gönderme Rehberi

Bilgisayara döndüğünde bu adımları takip et.

---

## Adım 1: GitHub Security Advisory (3 ayrı advisory)

Her biri için: https://github.com/glejeune/node-graphviz/security/advisories/new

---

### Advisory #1 — Code Injection via eval()

**Ecosystem:** npm
**Package name:** graphviz
**Affected versions:** <= 0.0.9
**Patched versions:** (boş bırak)
**Severity:** High

**Summary:**
Code Injection via eval() in parse() function

**Description:**
```
The `graphviz.parse()` function in `lib/graphviz.js` (line 48) executes `eval()` on the stdout of the `gvpr` command-line tool without sanitization.

The gvpr script `lib/ext/gvpr/dot2js.g` converts DOT files to JavaScript but fails to escape double quotes in:
- Node names (line 109): raw `$.name` inserted into printf format string
- Attribute values (lines 116, 145): only single quotes escaped via `gsub(attrv, "'", "\\'")`
- Edge endpoints (line 138): raw `$.tail.name` and `$.head.name`

An attacker who supplies a crafted `.dot` file to `graphviz.parse()` can break out of string literals and inject arbitrary JavaScript that executes in the Node.js process.

### PoC

A DOT file with a node name containing double quotes:

digraph exploit {
  "x"+process.mainModule.require('child_process').execSync('id').toString()+"y" [label="test"];
}

When parsed, gvpr generates JavaScript where the unescaped double quotes close the string literal, and the injected code is executed by eval().

### Impact

Remote Code Execution (RCE) in the Node.js process. An attacker can execute arbitrary system commands.

### References

- https://github.com/yasinfarukkilic/graphviz-cve
- CWE-94: Improper Control of Generation of Code
```

**CWE:** CWE-94

---

### Advisory #2 — DOT Injection

**Ecosystem:** npm
**Package name:** graphviz
**Affected versions:** <= 0.0.9
**Patched versions:** (boş bırak)
**Severity:** Moderate

**Summary:**
DOT Language Injection via unescaped special characters in output generation

**Description:**
```
Multiple functions in the graphviz package fail to escape double quotes when generating DOT output:

1. `lib/deps/attributs.js:199` — quoteMe() wraps values in double quotes without escaping
2. `lib/deps/node.js:56` — Node.to_dot() wraps node IDs without escaping
3. `lib/deps/edge.js:55` — Edge.to_dot() wraps edge node IDs without escaping

An attacker can inject arbitrary DOT attributes and graph elements by including double quotes in node IDs or attribute values.

### PoC

const graphviz = require('graphviz');
const g = graphviz.digraph('test');
const n = g.addNode('B');
n.set('label', 'hello"; URL="https://evil.com"; label="click me');
console.log(g.to_dot());

Output:
"B" [ label = "hello"; URL="https://evil.com"; label="click me" ]

The attacker injected a URL attribute. When rendered to SVG, this creates a clickable link to an attacker-controlled domain.

### Impact

- Inject arbitrary graph attributes (URL, href for phishing/redirect)
- Inject additional nodes and edges
- Potential XSS in SVG output via HTML-like labels

### References

- https://github.com/yasinfarukkilic/graphviz-cve
- CWE-74: Improper Neutralization of Special Elements in Output
```

**CWE:** CWE-74

---

### Advisory #3 — Prototype Pollution

**Ecosystem:** npm
**Package name:** graphviz
**Affected versions:** <= 0.0.9
**Patched versions:** (boş bırak)
**Severity:** Low

**Summary:**
Prototype Pollution via for..in loop in render() leads to CLI argument injection

**Description:**
```
The render() method in `lib/deps/graph.js` (lines 320, 329, 338) uses for..in loops to iterate over option objects without filtering prototype chain properties:

for( attr in type_or_options.G ) {
    parameters.push( "-G"+attr+"="+type_or_options.G[attr] )
}

If Object.prototype has been polluted by another vulnerability, the polluted properties are included in the iteration, injecting additional CLI arguments to the graphviz command.

### PoC

Object.prototype.injected = "malicious_value";
// Now render() produces extra parameter: -Ginjected=malicious_value

### Impact

Inject additional CLI arguments to graphviz commands when combined with a separate prototype pollution source.

### References

- https://github.com/yasinfarukkilic/graphviz-cve
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
```

**CWE:** CWE-1321

---

## Adım 2: MITRE CVE Başvurusu (opsiyonel)

GitHub GHSA otomatik CVE verebilir. Vermezse:
https://cveform.mitre.org/

- **Request Type:** Report Vulnerability/Request CVE ID
- **Vendor:** glejeune (npm: graphviz)
- **Product:** graphviz
- **Version:** 0.0.9 and earlier
- Her açık için ayrı başvuru yap

---

## Özet

| # | Açık | Nereye gönder | Link |
|---|------|---------------|------|
| 1 | eval() RCE | GitHub Advisory | https://github.com/glejeune/node-graphviz/security/advisories/new |
| 2 | DOT Injection | GitHub Advisory | https://github.com/glejeune/node-graphviz/security/advisories/new |
| 3 | Prototype Pollution | GitHub Advisory | https://github.com/glejeune/node-graphviz/security/advisories/new |
