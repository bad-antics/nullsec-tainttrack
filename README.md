# NullSec TaintTrack

**Taint Analysis Engine**

A static taint analysis tool written in OCaml, demonstrating functional programming with strong static typing for vulnerability detection through data flow analysis.

![OCaml](https://img.shields.io/badge/OCaml-EC6813?style=for-the-badge&logo=ocaml&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 🎯 Overview

NullSec TaintTrack performs static taint analysis to trace data flow from untrusted sources (user input, network data) to security-sensitive sinks (SQL queries, command execution), identifying injection vulnerabilities.

## ✨ Features

- **Source Tracking** - Monitor user input, network data, file reads
- **Sink Detection** - SQL queries, command execution, file writes
- **Flow Analysis** - Trace data through program paths
- **Sanitizer Recognition** - Detect when data is properly sanitized
- **CWE Mapping** - Common Weakness Enumeration references
- **MITRE ATT&CK** - Technique identification

## 🔍 Vulnerability Detection

| Vulnerability | Source → Sink | CWE | MITRE |
|--------------|---------------|-----|-------|
| SQL Injection | UserInput → SQLQuery | CWE-89 | T1190 |
| Command Injection | UserInput → CommandExec | CWE-78 | T1059 |
| XSS | UserInput → HTMLOutput | CWE-79 | T1189 |
| Path Traversal | UserInput → FileWrite | CWE-22 | T1083 |
| SSRF | UserInput → NetworkSend | CWE-918 | T1090 |
| Log Injection | UserInput → LogOutput | CWE-117 | T1070 |
| Code Injection | UserInput → Eval | CWE-94 | T1059 |

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/bad-antics/nullsec-tainttrack
cd nullsec-tainttrack

# Compile with ocamlfind
ocamlfind ocamlopt -o tainttrack tainttrack.ml

# Or compile with ocamlopt directly
ocamlopt -o tainttrack tainttrack.ml

# Run without compilation
ocaml tainttrack.ml
```

## 🚀 Usage

```bash
# Analyze source directory
./tainttrack src/

# JSON output
./tainttrack -j project/

# Verbose mode
./tainttrack -v app/

# List sources and sinks
./tainttrack --sources
./tainttrack --sinks

# Run demo mode
./tainttrack
```

## 💻 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║            NullSec TaintTrack - Taint Analysis Engine            ║
╚══════════════════════════════════════════════════════════════════╝

[Demo Mode]

Analyzing sample taint flows...

Analyzed 7 flows, found 6 vulnerabilities

  [CRITICAL] SQL Injection
    Source:  USER_INPUT
    Sink:    SQL_QUERY
    CWE:     CWE-89
    MITRE:   T1190

    Data Flow:
      → request.params['id'] (app.py:45)
      → user_id (app.py:46)
      → db.execute(query) (app.py:50)

  [CRITICAL] Command Injection
    Source:  NETWORK_DATA
    Sink:    COMMAND_EXEC
    CWE:     CWE-78
    MITRE:   T1059

    Data Flow:
      → socket.recv() (server.py:100)
      → cmd_data (server.py:101)
      → os.system(cmd) (server.py:105)

  [HIGH] Cross-Site Scripting
    Source:  USER_INPUT
    Sink:    HTML_OUTPUT
    CWE:     CWE-79
    MITRE:   T1189

    Data Flow:
      → request.args['name'] (views.py:20)
      → username (views.py:21)
      → render_template() (views.py:25)

═══════════════════════════════════════════

  Summary:
    Total Findings: 6
    Critical:       2
    High:           3
    Medium:         1
    Low:            0
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Source Code Parser                        │
│              Python | JavaScript | Java | PHP               │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Data Flow Graph Builder                     │
│         Track variable assignments and propagation          │
└─────────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
     ┌──────────┐   ┌──────────┐   ┌──────────┐
     │  Source  │   │Propagate │   │   Sink   │
     │  Finder  │   │  Taint   │   │  Finder  │
     └──────────┘   └──────────┘   └──────────┘
           │               │               │
           └───────────────┼───────────────┘
                           ▼
                   ┌──────────────┐
                   │Vulnerability │
                   │Classification│
                   └──────────────┘
```

## λ OCaml Features Demonstrated

- **Variant Types** - `taint_source`, `taint_sink`, `vulnerability`
- **Pattern Matching** - Exhaustive case analysis
- **Option Types** - `vulnerability option` for maybe values
- **Records** - `flow_node`, `taint_flow`, `finding`
- **Higher-Order Functions** - `List.filter_map`, `List.iter`
- **Modules** - `Color` module for ANSI codes
- **Type Inference** - Automatic type deduction
- **Immutability** - Default immutable data structures

## 🔧 Type Definitions

```ocaml
(* Taint flow record *)
type taint_flow = {
  source: taint_source;
  sink: taint_sink;
  nodes: flow_node list;
  vulnerability: vulnerability option;
}

(* Analysis finding *)
type finding = {
  severity: severity;
  flow: taint_flow;
  description: string;
  cwe: string;
}
```

## 📊 Taint Sources

| Source | Description |
|--------|-------------|
| UserInput | HTTP parameters, form data |
| NetworkData | Socket recv, API responses |
| FileRead | File contents |
| EnvironmentVar | Environment variables |
| DatabaseQuery | Database results |
| ExternalAPI | Third-party API data |
| CommandLine | CLI arguments |

## 🛡️ Security Use Cases

- **SAST** - Static Application Security Testing
- **Code Review** - Automated vulnerability detection
- **CI/CD Integration** - Pre-commit security checks
- **Compliance** - OWASP Top 10 detection
- **Training** - Security awareness examples

## ⚠️ Legal Disclaimer

This tool is intended for:
- ✅ Authorized code review
- ✅ Security testing of owned applications
- ✅ Educational purposes
- ✅ Research and development

**Only analyze code you're authorized to review.**

## 🔗 Links

- **Portal**: [bad-antics.github.io](https://bad-antics.github.io)
- **Discord**: [x.com/AnonAntics](https://x.com/AnonAntics)
- **GitHub**: [github.com/bad-antics](https://github.com/bad-antics)

## 📄 License

MIT License - See LICENSE file for details.

## 🏷️ Version History

- **v1.0.0** - Initial release with taint analysis and vulnerability classification

---

*Part of the NullSec Security Toolkit*
