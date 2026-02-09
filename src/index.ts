#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";

// ANSI colors
const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m",
};

interface RegexFinding {
  file: string;
  line: number;
  column: number;
  pattern: string;
  severity: "low" | "medium" | "high" | "critical";
  vulnerability: string;
  description: string;
  suggestion?: string;
}

interface ScanResult {
  files: number;
  findings: RegexFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const HELP = `
${c.bold}${c.cyan}redos-check${c.reset} - Find regex denial-of-service vulnerabilities

${c.bold}USAGE${c.reset}
  ${c.green}npx @lxgicstudios/redos-check${c.reset} [options] [files/dirs...]
  ${c.green}npx @lxgicstudios/redos-check${c.reset} src/           ${c.dim}# scan directory${c.reset}
  ${c.green}npx @lxgicstudios/redos-check${c.reset} app.js util.ts  ${c.dim}# scan specific files${c.reset}

${c.bold}OPTIONS${c.reset}
  --help              Show this help message
  --json              Output results as JSON
  --fix               Show suggested safe alternatives
  --ci                Exit with code 1 if vulnerabilities found
  --severity <level>  Minimum severity to report (low|medium|high|critical)
  --ignore <pattern>  Glob pattern to ignore (can repeat)
  --no-color          Disable colored output

${c.bold}EXAMPLES${c.reset}
  ${c.dim}# Scan current directory${c.reset}
  npx @lxgicstudios/redos-check .

  ${c.dim}# CI mode with fix suggestions${c.reset}
  npx @lxgicstudios/redos-check --ci --fix src/

  ${c.dim}# JSON output for tooling${c.reset}
  npx @lxgicstudios/redos-check --json src/

  ${c.dim}# Only show high+ severity${c.reset}
  npx @lxgicstudios/redos-check --severity high .
`;

function parseArgs(argv: string[]) {
  const args = {
    help: false,
    json: false,
    fix: false,
    ci: false,
    severity: "low" as "low" | "medium" | "high" | "critical",
    ignore: [] as string[],
    noColor: false,
    targets: [] as string[],
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--help":
      case "-h":
        args.help = true;
        break;
      case "--json":
        args.json = true;
        break;
      case "--fix":
        args.fix = true;
        break;
      case "--ci":
        args.ci = true;
        break;
      case "--severity":
        args.severity = (argv[++i] || "low") as any;
        break;
      case "--ignore":
        args.ignore.push(argv[++i] || "");
        break;
      case "--no-color":
        args.noColor = true;
        break;
      default:
        if (!arg.startsWith("-")) {
          args.targets.push(arg);
        }
        break;
    }
  }

  if (args.targets.length === 0) {
    args.targets.push(".");
  }

  return args;
}

// Vulnerability patterns that cause catastrophic backtracking
interface VulnPattern {
  name: string;
  detect: (pattern: string) => boolean;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  suggest: (pattern: string) => string;
}

const VULN_PATTERNS: VulnPattern[] = [
  {
    name: "Nested Quantifiers",
    detect: (p: string) => {
      // (a+)+ or (a*)+ or (a+)* etc.
      return /\([^)]*[+*]\)[+*]/.test(p) || /\([^)]*[+*]\)\{/.test(p);
    },
    severity: "critical",
    description:
      "Nested quantifiers cause exponential backtracking. An attacker can craft input that takes exponential time to match.",
    suggest: (p: string) =>
      p.replace(/\(([^)]*[+*])\)([+*])/, "(?>$1)$2") +
      " (use atomic groups or rewrite to avoid nesting)",
  },
  {
    name: "Overlapping Alternation with Quantifier",
    detect: (p: string) => {
      // (a|a)* or (a|ab)+ etc.
      return /\([^)]*\|[^)]*\)[+*]/.test(p) && hasOverlap(p);
    },
    severity: "critical",
    description:
      "Overlapping alternation branches under a quantifier cause exponential backtracking when the regex engine tries all combinations.",
    suggest: () => "Rewrite alternation to eliminate overlap between branches",
  },
  {
    name: "Star-of-Star",
    detect: (p: string) => /\.\*.*\.\*/.test(p) && /[+*]\)?\s*[+*]/.test(p),
    severity: "high",
    description: "Multiple greedy wildcards can cause polynomial backtracking.",
    suggest: () => "Use non-greedy quantifiers (.*?) or anchor the pattern",
  },
  {
    name: "Repetition of Repetition",
    detect: (p: string) => {
      // a{n}{m} or a+{n}
      return /[+*]\{/.test(p) || /\}\{/.test(p) || /\}[+*]/.test(p);
    },
    severity: "high",
    description: "Repeated quantifiers create exponential matching possibilities.",
    suggest: (p: string) => "Flatten nested repetitions into a single quantifier",
  },
  {
    name: "Greedy Quantifier Before Same Character Class",
    detect: (p: string) => {
      // .*\s or \s+\s or \w+\w
      const charClasses = ["\\w", "\\d", "\\s", "."];
      for (const cls of charClasses) {
        const escaped = cls.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        if (new RegExp(`${escaped}[+*].*${escaped}`).test(p)) {
          return true;
        }
      }
      return false;
    },
    severity: "medium",
    description:
      "A greedy quantifier followed by a pattern that can match the same characters may cause excessive backtracking.",
    suggest: () =>
      "Use possessive quantifiers, atomic groups, or make the first quantifier non-greedy",
  },
  {
    name: "Unbounded Repetition with Backtracking",
    detect: (p: string) => {
      // .+ or .* without anchors in complex patterns
      return (
        /\.\+[^?]/.test(p) && p.length > 10 && !p.startsWith("^") && !p.endsWith("$")
      );
    },
    severity: "low",
    description:
      "Unbounded greedy quantifiers in complex unanchored patterns can cause slowdowns with certain inputs.",
    suggest: () => "Add anchors (^ and $) or use non-greedy quantifiers (.*?)",
  },
  {
    name: "Exponential Backtracking via Group Reference",
    detect: (p: string) => {
      // backreferences with quantifiers: (a+)\1+
      return /\\[1-9][+*]/.test(p) || /\\[1-9]\{/.test(p);
    },
    severity: "high",
    description:
      "Backreferences combined with quantifiers can lead to exponential backtracking.",
    suggest: () =>
      "Avoid quantifiers on backreferences, or validate input length first",
  },
];

function hasOverlap(pattern: string): boolean {
  // Simple overlap detection: check if alternation branches share common prefixes
  const match = pattern.match(/\(([^)]+)\)/);
  if (!match) return false;
  const branches = match[1].split("|");
  if (branches.length < 2) return false;

  for (let i = 0; i < branches.length; i++) {
    for (let j = i + 1; j < branches.length; j++) {
      const a = branches[i].replace(/[+*?{}[\]\\]/g, "");
      const b = branches[j].replace(/[+*?{}[\]\\]/g, "");
      if (a.length > 0 && b.length > 0) {
        // Check if they share a common starting character
        if (a[0] === b[0] || a[0] === "." || b[0] === ".") return true;
        // Check if one contains the other
        if (a.includes(b) || b.includes(a)) return true;
      }
    }
  }
  return false;
}

function extractRegexPatterns(
  content: string,
  filePath: string
): Array<{ pattern: string; line: number; column: number }> {
  const results: Array<{ pattern: string; line: number; column: number }> = [];
  const lines = content.split("\n");

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    const line = lines[lineNum];

    // Match regex literals: /pattern/flags
    const regexLiteralRe = /(?:^|[=(:,;!&|?+\-~^%*/\s])(\/((?:[^/\\]|\\.)(?:[^/\\]|\\.)*)\/(g?i?m?s?u?y?d?)*)/g;
    let match: RegExpExecArray | null;

    while ((match = regexLiteralRe.exec(line)) !== null) {
      const fullMatch = match[1];
      const pattern = match[2];
      if (pattern && pattern.length > 1) {
        results.push({
          pattern,
          line: lineNum + 1,
          column: match.index + (fullMatch.indexOf("/") + 1),
        });
      }
    }

    // Match new RegExp("pattern") or new RegExp('pattern')
    const regExpConstructorRe = /new\s+RegExp\(\s*["'`]([^"'`]+)["'`]/g;
    while ((match = regExpConstructorRe.exec(line)) !== null) {
      results.push({
        pattern: match[1],
        line: lineNum + 1,
        column: match.index,
      });
    }
  }

  return results;
}

function analyzePattern(
  pattern: string,
  file: string,
  line: number,
  column: number,
  showFix: boolean
): RegexFinding[] {
  const findings: RegexFinding[] = [];

  for (const vuln of VULN_PATTERNS) {
    try {
      if (vuln.detect(pattern)) {
        findings.push({
          file,
          line,
          column,
          pattern,
          severity: vuln.severity,
          vulnerability: vuln.name,
          description: vuln.description,
          suggestion: showFix ? vuln.suggest(pattern) : undefined,
        });
      }
    } catch {
      // Skip detection errors for malformed patterns
    }
  }

  return findings;
}

function collectFiles(
  targets: string[],
  ignore: string[]
): string[] {
  const files: string[] = [];
  const extensions = new Set([".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".mts", ".cts"]);
  const ignoreDirs = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "__pycache__"]);

  function walk(dir: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (!ignoreDirs.has(entry.name) && !ignore.some((ig) => entry.name.includes(ig))) {
          walk(fullPath);
        }
      } else if (entry.isFile() && extensions.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
  }

  for (const target of targets) {
    const stat = fs.statSync(target, { throwIfNoEntry: false });
    if (!stat) {
      console.error(`${c.red}Warning:${c.reset} ${target} not found, skipping`);
      continue;
    }

    if (stat.isDirectory()) {
      walk(target);
    } else if (stat.isFile()) {
      files.push(target);
    }
  }

  return files;
}

const SEVERITY_ORDER: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function getSeverityColor(severity: string): string {
  switch (severity) {
    case "critical":
      return `${c.bgRed}${c.white}`;
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    case "low":
      return c.blue;
    default:
      return c.reset;
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity) {
    case "critical":
      return "💀";
    case "high":
      return "🔴";
    case "medium":
      return "⚠️";
    case "low":
      return "🔵";
    default:
      return "?";
  }
}

function printFinding(finding: RegexFinding) {
  const sevColor = getSeverityColor(finding.severity);
  const emoji = getSeverityEmoji(finding.severity);

  console.log(
    `\n  ${emoji} ${sevColor}${c.bold}${finding.severity.toUpperCase()}${c.reset} ${c.bold}${finding.vulnerability}${c.reset}`
  );
  console.log(
    `     ${c.dim}${finding.file}:${finding.line}:${finding.column}${c.reset}`
  );
  console.log(`     ${c.cyan}Pattern:${c.reset} /${finding.pattern}/`);
  console.log(`     ${finding.description}`);

  if (finding.suggestion) {
    console.log(`     ${c.green}Fix:${c.reset} ${finding.suggestion}`);
  }
}

function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    console.log(HELP);
    process.exit(0);
  }

  const files = collectFiles(args.targets, args.ignore);

  if (files.length === 0) {
    console.log(`${c.yellow}No JS/TS files found to scan.${c.reset}`);
    process.exit(0);
  }

  if (!args.json) {
    console.log(
      `\n${c.bold}${c.cyan}redos-check${c.reset} ${c.dim}Scanning ${files.length} file(s) for ReDoS vulnerabilities...${c.reset}\n`
    );
  }

  const allFindings: RegexFinding[] = [];
  const minSeverity = SEVERITY_ORDER[args.severity] || 0;

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }

    const patterns = extractRegexPatterns(content, file);

    for (const { pattern, line, column } of patterns) {
      const findings = analyzePattern(pattern, file, line, column, args.fix);
      const filtered = findings.filter(
        (f) => SEVERITY_ORDER[f.severity] >= minSeverity
      );
      allFindings.push(...filtered);
    }
  }

  // Sort by severity (critical first)
  allFindings.sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
  );

  const result: ScanResult = {
    files: files.length,
    findings: allFindings,
    summary: {
      total: allFindings.length,
      critical: allFindings.filter((f) => f.severity === "critical").length,
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
    },
  };

  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    if (allFindings.length === 0) {
      console.log(`  ${c.green}${c.bold}No ReDoS vulnerabilities found!${c.reset} ✅`);
      console.log(`  ${c.dim}Scanned ${files.length} file(s)${c.reset}\n`);
    } else {
      for (const finding of allFindings) {
        printFinding(finding);
      }

      console.log(`\n${c.bold}${"─".repeat(50)}${c.reset}`);
      console.log(`${c.bold}Summary${c.reset} - ${files.length} files scanned`);
      console.log(
        `  ${c.bgRed}${c.white} Critical: ${result.summary.critical} ${c.reset}  ` +
          `${c.red}High: ${result.summary.high}${c.reset}  ` +
          `${c.yellow}Medium: ${result.summary.medium}${c.reset}  ` +
          `${c.blue}Low: ${result.summary.low}${c.reset}`
      );
      console.log(
        `  ${c.bold}Total: ${allFindings.length} vulnerability(ies)${c.reset}\n`
      );
    }
  }

  if (args.ci && allFindings.length > 0) {
    process.exit(1);
  }
}

main();
