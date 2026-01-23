(* NullSec TaintTrack - Taint Analysis Engine *)
(* OCaml security tool demonstrating:
     - Strong static typing with type inference
     - Pattern matching on algebraic types
     - Immutable data by default
     - Functional programming
     - Module system
     - Variant types
   
   Author: bad-antics
   License: MIT *)

let version = "1.0.0"

(* ANSI Colors *)
module Color = struct
  let red    = "\x1b[31m"
  let green  = "\x1b[32m"
  let yellow = "\x1b[33m"
  let cyan   = "\x1b[36m"
  let gray   = "\x1b[90m"
  let reset  = "\x1b[0m"
end

(* Severity type *)
type severity = 
  | Critical 
  | High 
  | Medium 
  | Low 
  | Info

let severity_to_string = function
  | Critical -> "CRITICAL"
  | High -> "HIGH"
  | Medium -> "MEDIUM"
  | Low -> "LOW"
  | Info -> "INFO"

let severity_color = function
  | Critical | High -> Color.red
  | Medium -> Color.yellow
  | Low -> Color.cyan
  | Info -> Color.gray

(* Taint source types *)
type taint_source =
  | UserInput
  | NetworkData
  | FileRead
  | EnvironmentVar
  | DatabaseQuery
  | ExternalAPI
  | CommandLine

let source_to_string = function
  | UserInput -> "USER_INPUT"
  | NetworkData -> "NETWORK_DATA"
  | FileRead -> "FILE_READ"
  | EnvironmentVar -> "ENV_VAR"
  | DatabaseQuery -> "DATABASE"
  | ExternalAPI -> "EXTERNAL_API"
  | CommandLine -> "COMMAND_LINE"

(* Taint sink types *)
type taint_sink =
  | SQLQuery
  | CommandExec
  | FileWrite
  | NetworkSend
  | HTMLOutput
  | LogOutput
  | Eval

let sink_to_string = function
  | SQLQuery -> "SQL_QUERY"
  | CommandExec -> "COMMAND_EXEC"
  | FileWrite -> "FILE_WRITE"
  | NetworkSend -> "NETWORK_SEND"
  | HTMLOutput -> "HTML_OUTPUT"
  | LogOutput -> "LOG_OUTPUT"
  | Eval -> "EVAL"

(* Vulnerability type *)
type vulnerability =
  | SQLInjection
  | CommandInjection
  | XSS
  | PathTraversal
  | SSRF
  | LogInjection
  | CodeInjection

let vuln_to_string = function
  | SQLInjection -> "SQL Injection"
  | CommandInjection -> "Command Injection"
  | XSS -> "Cross-Site Scripting"
  | PathTraversal -> "Path Traversal"
  | SSRF -> "Server-Side Request Forgery"
  | LogInjection -> "Log Injection"
  | CodeInjection -> "Code Injection"

let vuln_mitre = function
  | SQLInjection -> "T1190"
  | CommandInjection -> "T1059"
  | XSS -> "T1189"
  | PathTraversal -> "T1083"
  | SSRF -> "T1090"
  | LogInjection -> "T1070"
  | CodeInjection -> "T1059"

(* Data flow node *)
type flow_node = {
  id: int;
  name: string;
  file: string;
  line: int;
  is_sanitized: bool;
}

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

(* Determine vulnerability from source-sink pair *)
let classify_vulnerability source sink =
  match (source, sink) with
  | (UserInput, SQLQuery) -> Some SQLInjection
  | (NetworkData, SQLQuery) -> Some SQLInjection
  | (UserInput, CommandExec) -> Some CommandInjection
  | (NetworkData, CommandExec) -> Some CommandInjection
  | (UserInput, HTMLOutput) -> Some XSS
  | (DatabaseQuery, HTMLOutput) -> Some XSS
  | (UserInput, FileWrite) -> Some PathTraversal
  | (UserInput, NetworkSend) -> Some SSRF
  | (NetworkData, NetworkSend) -> Some SSRF
  | (UserInput, LogOutput) -> Some LogInjection
  | (UserInput, Eval) -> Some CodeInjection
  | (NetworkData, Eval) -> Some CodeInjection
  | _ -> None

(* Get severity for vulnerability *)
let vuln_severity = function
  | SQLInjection -> Critical
  | CommandInjection -> Critical
  | CodeInjection -> Critical
  | XSS -> High
  | PathTraversal -> High
  | SSRF -> High
  | LogInjection -> Medium

(* Get CWE for vulnerability *)
let vuln_cwe = function
  | SQLInjection -> "CWE-89"
  | CommandInjection -> "CWE-78"
  | XSS -> "CWE-79"
  | PathTraversal -> "CWE-22"
  | SSRF -> "CWE-918"
  | LogInjection -> "CWE-117"
  | CodeInjection -> "CWE-94"

(* Analyze a taint flow *)
let analyze_flow flow =
  let is_sanitized = List.exists (fun n -> n.is_sanitized) flow.nodes in
  if is_sanitized then
    None
  else
    match classify_vulnerability flow.source flow.sink with
    | Some vuln ->
      Some {
        severity = vuln_severity vuln;
        flow = { flow with vulnerability = Some vuln };
        description = Printf.sprintf 
          "Unsanitized %s flows to %s" 
          (source_to_string flow.source) 
          (sink_to_string flow.sink);
        cwe = vuln_cwe vuln;
      }
    | None -> None

(* Demo taint flows *)
let demo_flows () = [
  (* SQL Injection *)
  {
    source = UserInput;
    sink = SQLQuery;
    nodes = [
      { id = 1; name = "request.params['id']"; file = "app.py"; line = 45; is_sanitized = false };
      { id = 2; name = "user_id"; file = "app.py"; line = 46; is_sanitized = false };
      { id = 3; name = "db.execute(query)"; file = "app.py"; line = 50; is_sanitized = false };
    ];
    vulnerability = None;
  };
  (* Command Injection *)
  {
    source = NetworkData;
    sink = CommandExec;
    nodes = [
      { id = 4; name = "socket.recv()"; file = "server.py"; line = 100; is_sanitized = false };
      { id = 5; name = "cmd_data"; file = "server.py"; line = 101; is_sanitized = false };
      { id = 6; name = "os.system(cmd)"; file = "server.py"; line = 105; is_sanitized = false };
    ];
    vulnerability = None;
  };
  (* XSS *)
  {
    source = UserInput;
    sink = HTMLOutput;
    nodes = [
      { id = 7; name = "request.args['name']"; file = "views.py"; line = 20; is_sanitized = false };
      { id = 8; name = "username"; file = "views.py"; line = 21; is_sanitized = false };
      { id = 9; name = "render_template()"; file = "views.py"; line = 25; is_sanitized = false };
    ];
    vulnerability = None;
  };
  (* Sanitized flow - should not report *)
  {
    source = UserInput;
    sink = SQLQuery;
    nodes = [
      { id = 10; name = "request.params['q']"; file = "search.py"; line = 10; is_sanitized = false };
      { id = 11; name = "sanitize(query)"; file = "search.py"; line = 11; is_sanitized = true };
      { id = 12; name = "db.query(safe_q)"; file = "search.py"; line = 15; is_sanitized = false };
    ];
    vulnerability = None;
  };
  (* Path Traversal *)
  {
    source = UserInput;
    sink = FileWrite;
    nodes = [
      { id = 13; name = "request.files['upload']"; file = "upload.py"; line = 30; is_sanitized = false };
      { id = 14; name = "filename"; file = "upload.py"; line = 31; is_sanitized = false };
      { id = 15; name = "open(path, 'w')"; file = "upload.py"; line = 35; is_sanitized = false };
    ];
    vulnerability = None;
  };
  (* SSRF *)
  {
    source = UserInput;
    sink = NetworkSend;
    nodes = [
      { id = 16; name = "params['url']"; file = "proxy.py"; line = 50; is_sanitized = false };
      { id = 17; name = "target_url"; file = "proxy.py"; line = 51; is_sanitized = false };
      { id = 18; name = "requests.get(url)"; file = "proxy.py"; line = 55; is_sanitized = false };
    ];
    vulnerability = None;
  };
  (* Log Injection *)
  {
    source = UserInput;
    sink = LogOutput;
    nodes = [
      { id = 19; name = "request.headers['User-Agent']"; file = "middleware.py"; line = 10; is_sanitized = false };
      { id = 20; name = "user_agent"; file = "middleware.py"; line = 11; is_sanitized = false };
      { id = 21; name = "logger.info()"; file = "middleware.py"; line = 15; is_sanitized = false };
    ];
    vulnerability = None;
  };
]

(* Print banner *)
let print_banner () =
  print_endline "";
  print_endline "╔══════════════════════════════════════════════════════════════════╗";
  print_endline "║            NullSec TaintTrack - Taint Analysis Engine            ║";
  print_endline "╚══════════════════════════════════════════════════════════════════╝";
  print_endline ""

(* Print usage *)
let print_usage () =
  print_endline "USAGE:";
  print_endline "    tainttrack [OPTIONS] <source_dir>";
  print_endline "";
  print_endline "OPTIONS:";
  print_endline "    -h, --help       Show this help";
  print_endline "    -j, --json       JSON output";
  print_endline "    -v, --verbose    Verbose output";
  print_endline "    --sources        List configured sources";
  print_endline "    --sinks          List configured sinks";
  print_endline "";
  print_endline "SUPPORTED LANGUAGES:";
  print_endline "    • Python";
  print_endline "    • JavaScript";
  print_endline "    • Java";
  print_endline "    • PHP"

(* Print finding *)
let print_finding finding =
  let col = severity_color finding.severity in
  let sev = severity_to_string finding.severity in
  let flow = finding.flow in
  let vuln_name = match flow.vulnerability with
    | Some v -> vuln_to_string v
    | None -> "Unknown"
  in
  let mitre = match flow.vulnerability with
    | Some v -> vuln_mitre v
    | None -> "N/A"
  in
  print_endline "";
  Printf.printf "  %s[%s]%s %s\n" col sev Color.reset vuln_name;
  Printf.printf "    Source:  %s\n" (source_to_string flow.source);
  Printf.printf "    Sink:    %s\n" (sink_to_string flow.sink);
  Printf.printf "    CWE:     %s\n" finding.cwe;
  Printf.printf "    MITRE:   %s\n" mitre;
  print_endline "";
  print_endline "    Data Flow:";
  List.iter (fun node ->
    let marker = if node.is_sanitized then "✓" else "→" in
    Printf.printf "      %s %s (%s:%d)\n" marker node.name node.file node.line
  ) flow.nodes

(* Print summary *)
let print_summary findings =
  let crit = List.length (List.filter (fun f -> f.severity = Critical) findings) in
  let high = List.length (List.filter (fun f -> f.severity = High) findings) in
  let med = List.length (List.filter (fun f -> f.severity = Medium) findings) in
  let low = List.length (List.filter (fun f -> f.severity = Low) findings) in
  print_endline "";
  Printf.printf "%s═══════════════════════════════════════════%s\n" Color.gray Color.reset;
  print_endline "";
  print_endline "  Summary:";
  Printf.printf "    Total Findings: %d\n" (List.length findings);
  Printf.printf "    Critical:       %s%d%s\n" Color.red crit Color.reset;
  Printf.printf "    High:           %s%d%s\n" Color.red high Color.reset;
  Printf.printf "    Medium:         %s%d%s\n" Color.yellow med Color.reset;
  Printf.printf "    Low:            %s%d%s\n" Color.cyan low Color.reset

(* Demo mode *)
let demo_mode () =
  Printf.printf "%s[Demo Mode]%s\n" Color.yellow Color.reset;
  print_endline "";
  Printf.printf "%sAnalyzing sample taint flows...%s\n" Color.cyan Color.reset;
  
  let flows = demo_flows () in
  let findings = List.filter_map analyze_flow flows in
  
  Printf.printf "\nAnalyzed %d flows, found %d vulnerabilities\n" 
    (List.length flows) (List.length findings);
  
  List.iter print_finding findings;
  print_summary findings

(* Main entry point *)
let () =
  print_banner ();
  let args = Array.to_list Sys.argv in
  match List.tl args with
  | [] -> print_usage (); print_endline ""; demo_mode ()
  | "-h" :: _ | "--help" :: _ -> print_usage ()
  | _ -> print_usage (); print_endline ""; demo_mode ()
