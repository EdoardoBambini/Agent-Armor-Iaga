use crate::core::types::{InspectRequest, ProtocolKind};

pub fn detect_protocol(input: &InspectRequest) -> ProtocolKind {
    if let Some(p) = input.protocol {
        return p;
    }

    let tool = input.action.tool_name.to_lowercase();
    let framework = input.framework.to_lowercase();

    // MCP
    if tool.contains("mcp") || framework.contains("mcp") {
        return ProtocolKind::Mcp;
    }

    // A2A (Google Agent-to-Agent protocol)
    if framework.contains("a2a") || tool.contains("a2a") {
        return ProtocolKind::A2a;
    }

    // Check payload for A2A task structure
    if input.action.payload.contains_key("taskId")
        || input.action.payload.contains_key("skill")
        || (input.action.payload.contains_key("message")
            && input.action.payload.contains_key("parts"))
    {
        return ProtocolKind::A2a;
    }

    // ACP
    if tool.contains("acp") || framework.contains("acp") {
        return ProtocolKind::Acp;
    }

    if !framework.is_empty() {
        return ProtocolKind::HttpFunction;
    }

    ProtocolKind::Unknown
}
