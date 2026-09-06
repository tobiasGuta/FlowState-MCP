# FlowState MCP

FlowState MCP is a local Model Context Protocol server for **persistent business-workflow and application-state analysis** during authorized web security testing.

It is not a vulnerability scanner and it does not send requests.

V1 imports local Burp XML or HAR traffic, assigns each import to a human-defined actor, strips authentication secrets, extracts workflow-relevant identifiers and state fields, builds an actor/entity/action/state graph, and proposes **hypotheses** for manual validation.

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

## V1 safety boundary

FlowState V1:

- uses local `stdio` MCP only;
- has no HTTP client;
- has no browser automation;
- has no scanner;
- has no exploit runner;
- does not replay requests;
- does not store Authorization, Cookie, Set-Cookie, API-key, password, or token values;
- filters imports to the campaign target host and its subdomains;
- uses bounded import sizes and bounded observation counts;
- labels hypotheses as requiring manual validation.

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
| `flow_generate_transition_hypotheses` | Generate replay/state-transition questions |
| `flow_generate_actor_swap_hypotheses` | Generate actor-comparison questions |

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
          Burp MCP
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

3. flow_register_actor
   actor_id="member"
   name="Member"
   roles=["organization_member"]

4. Export Owner traffic from Burp as XML or HAR.

5. flow_import_burp_xml
   campaign_id="..."
   actor_id="owner"
   path="D:/BugBounty/target/owner.xml"

6. Repeat for Member.

7. flow_build_state_graph

8. flow_show_actor_permissions

9. flow_generate_transition_hypotheses

10. flow_generate_actor_swap_hypotheses
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

If it cannot do that, we should improve the model before adding active features.

## License

MIT
