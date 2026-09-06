from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from flowstate import __version__
from flowstate.analyzer import actor_permissions as actor_permissions_logic
from flowstate.analyzer import build_graph as build_graph_logic
from flowstate.analyzer import object_history as object_history_logic
from flowstate.config import limits
from flowstate.hypotheses import actor_swap_hypotheses as actor_swap_hypotheses_logic
from flowstate.hypotheses import transition_hypotheses as transition_hypotheses_logic
from flowstate.importers import import_burp_xml as import_burp_xml_logic
from flowstate.importers import import_har as import_har_logic
from flowstate.store import (
    FlowStateError,
    create_campaign as create_campaign_logic,
    get_campaign as get_campaign_logic,
    list_actors as list_actors_logic,
    list_campaigns as list_campaigns_logic,
    list_observations as list_observations_logic,
    register_actor as register_actor_logic,
)

mcp = FastMCP("flowstate-mcp")

AVAILABLE_TOOLS = [
    "flow_health",
    "flow_create_campaign",
    "flow_list_campaigns",
    "flow_get_campaign",
    "flow_register_actor",
    "flow_list_actors",
    "flow_import_har",
    "flow_import_burp_xml",
    "flow_list_observations",
    "flow_build_state_graph",
    "flow_show_actor_permissions",
    "flow_show_object_history",
    "flow_generate_transition_hypotheses",
    "flow_generate_actor_swap_hypotheses",
]

@mcp.tool()
def flow_health() -> dict:
    """Return FlowState status and safety boundaries."""
    return {
        "ok": True,
        "project": "flowstate-mcp",
        "version": __version__,
        "available_tools": AVAILABLE_TOOLS,
        "limits": limits(),
        "network_access": False,
        "request_replay": False,
        "safety_note": (
            "FlowState V1 only imports local traffic artifacts, stores sanitized observations, "
            "builds workflow models, and generates hypotheses for manual validation."
        ),
        "burp_mcp_boundary": (
            "Use Burp MCP separately for controlled request inspection or replay. "
            "FlowState V1 intentionally does not send traffic."
        ),
    }

@mcp.tool()
def flow_create_campaign(name: str, target_host: str, notes: str | None = None) -> dict:
    """Create a local FlowState campaign for one authorized target host."""
    return create_campaign_logic(name, target_host, notes)

@mcp.tool()
def flow_list_campaigns(limit: int = 50) -> dict:
    """List local FlowState campaigns."""
    return {"campaigns": list_campaigns_logic(limit)}

@mcp.tool()
def flow_get_campaign(campaign_id: str) -> dict:
    """Return one FlowState campaign."""
    return get_campaign_logic(campaign_id)

@mcp.tool()
def flow_register_actor(campaign_id: str, actor_id: str, name: str, roles: list[str] | None = None, notes: str | None = None) -> dict:
    """Register a human-defined actor such as owner, member, outsider, or anonymous."""
    return register_actor_logic(campaign_id, actor_id, name, roles, notes)

@mcp.tool()
def flow_list_actors(campaign_id: str) -> dict:
    """List actors registered in a campaign."""
    return {"actors": list_actors_logic(campaign_id)}

@mcp.tool()
def flow_import_har(campaign_id: str, actor_id: str, path: str) -> dict:
    """Import a local HAR for one actor without replaying requests or storing secrets."""
    return import_har_logic(campaign_id, actor_id, path)

@mcp.tool()
def flow_import_burp_xml(campaign_id: str, actor_id: str, path: str) -> dict:
    """Import a local Burp XML export for one actor without replaying requests or storing secrets."""
    return import_burp_xml_logic(campaign_id, actor_id, path)

@mcp.tool()
def flow_list_observations(campaign_id: str, actor_id: str | None = None, limit: int = 200) -> dict:
    """List recent sanitized observations, optionally for one actor."""
    return {"observations": list_observations_logic(campaign_id, actor_id, limit)}

@mcp.tool()
def flow_build_state_graph(campaign_id: str) -> dict:
    """Build an actor/entity/action/state graph from current observations."""
    return build_graph_logic(campaign_id)

@mcp.tool()
def flow_show_actor_permissions(campaign_id: str) -> dict:
    """Summarize observed state-changing and read behavior by actor."""
    return actor_permissions_logic(campaign_id)

@mcp.tool()
def flow_show_object_history(campaign_id: str, entity_value: str) -> dict:
    """Show where one observed entity identifier appeared across the workflow."""
    return object_history_logic(campaign_id, entity_value)

@mcp.tool()
def flow_generate_transition_hypotheses(campaign_id: str, limit: int = 50) -> dict:
    """Generate replay and state-transition hypotheses from evidence; never claim a vulnerability."""
    return transition_hypotheses_logic(campaign_id, limit)

@mcp.tool()
def flow_generate_actor_swap_hypotheses(campaign_id: str, limit: int = 50) -> dict:
    """Generate actor-comparison hypotheses for state-changing actions; manual validation is required."""
    return actor_swap_hypotheses_logic(campaign_id, limit)

if __name__ == "__main__":
    mcp.run(transport="stdio")
