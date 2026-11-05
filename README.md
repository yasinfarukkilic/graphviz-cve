# graphviz npm package — Security Vulnerabilities

Multiple security vulnerabilities discovered in the [`graphviz`](https://www.npmjs.com/package/graphviz) npm package (v0.0.9, ~513K weekly downloads).

## Vulnerabilities

| # | CWE | Severity | Title |
|---|-----|----------|-------|
| 1 | CWE-94 | HIGH (8.1) | Code Injection via `eval()` in `parse()` |
| 2 | CWE-74 | MEDIUM (5.4) | DOT Injection via unescaped special characters |
| 3 | CWE-1321 | LOW (3.7) | Prototype Pollution via `for..in` in `render()` |

## Files

- [`GRAPHVIZ-VULNERABILITY-REPORT.md`](GRAPHVIZ-VULNERABILITY-REPORT.md) — Full vulnerability report
- [`graphviz-poc-1-dot-injection.js`](graphviz-poc-1-dot-injection.js) — PoC: DOT injection
- [`graphviz-poc-2-eval-injection.js`](graphviz-poc-2-eval-injection.js) — PoC: Code injection via eval()
- [`graphviz-poc-3-prototype-pollution.js`](graphviz-poc-3-prototype-pollution.js) — PoC: Prototype pollution

## Quick Start

```bash
npm install graphviz
node graphviz-poc-1-dot-injection.js
node graphviz-poc-2-eval-injection.js
node graphviz-poc-3-prototype-pollution.js
```

## Researcher

Yasin Faruk Kaya — yasinfarukk@gmail.com

## Disclosure

- **Package**: graphviz v0.0.9
- **Repository**: https://github.com/glejeune/node-graphviz
- **NPM**: https://www.npmjs.com/package/graphviz
