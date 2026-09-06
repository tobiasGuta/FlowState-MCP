# FlowState MCP

FlowState MCP is a local Model Context Protocol server for **persistent business-workflow and application-state analysis** during authorized web security testing.

It is not a vulnerability scanner and it does not send requests.

V1 imports local Burp XML or HAR traffic, assigns each import to a human-defined actor, strips authentication secrets, extracts workflow-relevant identifiers and state fields, builds an actor/entity/action/state graph, proposes **hypotheses** for manual validation, and can persist structured validation outcomes.

## Why it exists

Burp MCP is excellent at exposing HTTP traffic and controlled Burp actions to an AI client.

FlowState solves a different problem:

> What does the traffic mean in the application's workflow?

Examples:

```text
Owner creates invitation
        ↓
Member accepts invitation
        ↓
Membership becomes active
        ↓
Owner removes member
```

FlowState can remember the actors, objects, transitions, and evidence behind those actions and then suggest questions such as:

- Was an accepted invitation actually made unusable?
- Can another registered actor perform the same state-changing action?
- Did a field change from `pending` to `accepted`, and are invalid adjacent transitions still untested?
- Where did one object identifier appear across multiple requests?

Those are hypotheses, not vulnerability findings.

## Design principle: no target-specific heuristics

A lab or real target may reveal a weakness in FlowState's model, but the production fix must describe a **general web-workflow property**, not the target's route names or known solution.

FlowState must not special-case paths such as `/account`, `/checkout`, `/dashboard`, or any lab-specific endpoint. Instead, it should reason from evidence such as:

- chronological timestamps;
- session continuity and session rotation;
- redirects and sanitized Referer relationships;
- HTTP method and response semantics;
- observed state fields;
- the same endpoint changing from a redirect/denial-like response to a successful response.

Regression fixtures are allowed to resemble bugs that exposed a weakness. Production code is not.

## v0.1.3 workflow intelligence

v0.1.3 adds generic workflow-span reasoning on top of the v0.1.2 chronology model:

- redirect-follow GET/HEAD observations are identified as navigation edges;
- navigation that also rotates a session or carries state evidence remains a meaningful state boundary;
- the same endpoint changing from redirect to success is surfaced as an access-gate candidate;
- transition hypotheses are ranked by bug-hunting value;
- whole-span checkpoint hypotheses target the protected destination instead of only examining adjacent triples;
- low-value local skip hypotheses whose destination is merely a redirect-follow navigation request are suppressed.

For an observed span like:

```text
resource denied
      ↓
workflow step A
      ↓
workflow step B
      ↓
resource succeeds
```

FlowState can ask whether the resource becomes accessible immediately after A, before B is completed, without knowing anything about the application's path names.

## v0.1.4 evidence lifecycle

v0.1.4 keeps FlowState passive but lets it remember what happened when a human manually validates a generated hypothesis.

Generated hypotheses now receive stable campaign-local IDs plus a validation state:

```text
untested
   ↓
supported | falsified | inconclusive
```

`flow_record_hypothesis_validation` stores only structured, sanitized evidence such as:

- the hypothesis ID;
- manual outcome (`supported`, `falsified`, or `inconclusive`);
- test method and path;
- observed HTTP status;
- sanitized redirect path;
- a bounded note with obvious secret assignments redacted.

Query values are not persisted in validation paths. Cookies, session values, credentials, CSRF values, and token material are not required or intentionally stored.

A `supported` hypothesis still does **not** mean "confirmed vulnerability". It means manual evidence supported the security concern represented by that hypothesis. Reporting impact and vulnerability status remain separate human decisions.

The lifecycle becomes:

```text
passive traffic
      ↓
workflow model
      ↓
hypothesis (untested)
      ↓
manual validation outside FlowState
      ↓
record structured result
      ↓
supported / falsified / inconclusive
      ↓
regenerated hypothesis keeps that history
```

## V1 safety boundary

FlowState V1:

- uses local `stdio` MCP only;
- has no HTTP client;
- has no browser automation;
- has no scanner;
- has no exploit runner;
- does not replay requests;
- does not store Authorization, Cookie, Set-Cookie, API-key, password, or token values from imported traffic;
- filters imports to the campaign target host and its subdomains;
- uses bounded import sizes and bounded observation counts;
- labels hypotheses as requiring manual validation;
- records validation outcomes only after an external/manual test has already occurred.

Use your existing Burp MCP separately when you intentionally want the AI client to inspect or replay a request.

## Tools

| Tool | Purpose |
| --- | --- |
| `flow_health` | Server status, limits, and safety boundary |
| `flow_create_campaign` | Create one target-scoped workflow campaign |
| `flow_list_campaigns` | List local campaigns |
| `flow_get_campaign` | Read one campaign |
| `flow_register_actor` | Register Owner, Member, Outsider, Anonymous, etc. |
| `flow_list_actors` | List campaign actors |
| `flow_import_har` | Import a HAR for one actor |
| `flow_import_burp_xml` | Import Burp XML for one actor |
| `flow_list_observations` | Inspect sanitized stored observations |
| `flow_build_state_graph` | Build actor/entity/action/state relationships |
| `flow_show_actor_permissions` | Compare observed behavior by actor |
| `flow_show_object_history` | Trace one identifier across observations |
| `flow_generate_transition_hypotheses` | Generate ranked transition questions with persistent validation status |
| `flow_generate_actor_swap_hypotheses` | Generate actor-comparison questions with persistent validation status |
| `flow_record_hypothesis_validation` | Persist a structured manual validation outcome for a generated hypothesis |
| `flow_list_hypothesis_validations` | List validation history for a campaign or one hypothesis |

## Install

Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest -q
```

## Run manually

```bash
python server.py
```

The server speaks MCP over stdin/stdout, so manual launch normally appears to wait for protocol input.

## Codex registration

Windows example:

```powershell
codex mcp add flowstate -- D:/Tools/FlowState-MCP/.venv/Scripts/python.exe D:/Tools/FlowState-MCP/server.py
codex mcp get flowstate
```

Linux/macOS:

```bash
codex mcp add flowstate -- /absolute/path/FlowState-MCP/.venv/bin/python /absolute/path/FlowState-MCP/server.py
```

## Claude Code registration

```bash
claude mcp add flowstate --scope user -- /absolute/path/FlowState-MCP/.venv/bin/python /absolute/path/FlowState-MCP/server.py
```

## Suggested workflow with Burp MCP

```text
ScopeNest containers
  ├─ Owner
  ├─ Member
  └─ Anonymous
        │
        ↓
       Burp
        │
        ├──────────────→ Burp MCP
        │                  │
        │                  └─ inspect/replay intentionally
        │
        └─ export HAR/XML
              │
              ↓
         FlowState MCP
              │
     ┌────────┼─────────┐
     ↓        ↓         ↓
   actors   objects   states
     └────────┼─────────┘
              ↓
          hypotheses
              ↓
      manual validation
              ↓
      record safe result
              ↓
   supported / falsified /
        inconclusive
```

## Example session

```text
1. flow_create_campaign
   name="Target SaaS"
   target_host="app.example.com"

2. flow_register_actor
   actor_id="owner"
   name="Owner"
   roles=["organization_owner"]

3. Export Owner traffic from Burp as XML or HAR.

4. flow_import_burp_xml

5. flow_build_state_graph

6. flow_generate_transition_hypotheses
   # note the hypothesis_id of the question you manually test

7. Perform the controlled validation separately.

8. flow_record_hypothesis_validation
   hypothesis_id="hyp-..."
   outcome="supported"
   test_method="GET"
   test_path="/protected-resource"
   observed_status=200

9. flow_generate_transition_hypotheses
   # the same hypothesis now reports validation_status="supported"

10. flow_list_hypothesis_validations
```

## What V1 deliberately does not do

V1 does not try to infer a complete business ontology from every API field.

It uses deterministic heuristics for:

- action verbs in paths;
- HTTP method semantics;
- path identifiers;
- common ID-like JSON fields;
- common state/status/role fields.

The graph is evidence-backed and intentionally imperfect. A future version can add explicit human corrections such as:

```text
"mem_912 represents user_22"
"workspace_id is a tenant boundary"
"accepted invitations must never be reusable"
```

without turning guesses into facts.

## V1 success test

FlowState V1 is successful only if, on a real bug-bounty session, it produces at least one hypothesis that you would genuinely test and that you did not immediately notice from raw Burp history alone.

The next bar is stronger: the hypothesis should survive controlled manual validation and FlowState should preserve that evidence without turning a hypothesis into a vulnerability claim automatically.

## License

MIT
