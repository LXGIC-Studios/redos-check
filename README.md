# redos-check

[![npm version](https://img.shields.io/npm/v/@lxgicstudios/redos-check.svg)](https://www.npmjs.com/package/@lxgicstudios/redos-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Find regex denial-of-service (ReDoS) vulnerabilities in your JavaScript and TypeScript files. Detects catastrophic backtracking patterns, nested quantifiers, and overlapping alternation before attackers find them first.

## Install

```bash
# Run directly with npx
npx @lxgicstudios/redos-check src/

# Or install globally
npm install -g @lxgicstudios/redos-check
```

## Usage

```bash
# Scan a directory
redos-check src/

# Scan specific files
redos-check app.js utils.ts

# CI mode (exits with code 1 on findings)
redos-check --ci src/

# Show fix suggestions
redos-check --fix src/

# JSON output for tooling
redos-check --json src/

# Only show high severity and above
redos-check --severity high .
```

## Features

- **Zero dependencies** - uses only built-in Node.js modules
- Detects nested quantifiers like `(a+)+` that cause exponential backtracking
- Finds overlapping alternation under quantifiers like `(a|ab)*`
- Catches repetition-of-repetition patterns
- Identifies greedy wildcards that fight each other
- Scans both regex literals (`/pattern/`) and `new RegExp()` constructors
- Supports `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` files
- CI mode for pipeline integration
- Fix suggestions with `--fix` flag
- Configurable severity filtering

## Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--json` | Output results as JSON |
| `--fix` | Show suggested safe alternatives |
| `--ci` | Exit with code 1 if vulnerabilities found |
| `--severity <level>` | Minimum severity to report (low, medium, high, critical) |
| `--ignore <pattern>` | Pattern to ignore (repeatable) |
| `--no-color` | Disable colored output |

## Vulnerability Patterns Detected

| Pattern | Severity | Example |
|---------|----------|---------|
| Nested Quantifiers | Critical | `(a+)+`, `(a*)+`, `([a-z]+)*` |
| Overlapping Alternation | Critical | `(a\|a)*`, `(a\|ab)+` |
| Star-of-Star | High | `.*.*`, `(.+)+` |
| Repetition of Repetition | High | `a+{2}`, `a{2}{3}` |
| Greedy + Same Class | Medium | `\w+\w`, `\s+\s` |
| Unbounded Without Anchors | Low | `.+` in complex patterns |
| Backreference + Quantifier | High | `(a+)\1+` |

## Why ReDoS Matters

A single vulnerable regex can take your server down. When a regex has catastrophic backtracking, an attacker can craft input that takes seconds (or minutes) to process. That's all it takes for a denial-of-service attack.

This tool catches those patterns before they hit production.

## License

MIT - [LXGIC Studios](https://github.com/lxgicstudios)
