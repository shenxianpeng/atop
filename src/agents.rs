/// Keyword rule: when a process name contains `keyword` (case-insensitive), it is identified as the corresponding agent
struct AgentRule {
    keyword: &'static str,
    display: &'static str,
}

static RULES: &[AgentRule] = &[
    // More specific rules must come before broader ones (first match wins)
    AgentRule { keyword: "opencode",  display: "OpenCode" },
    AgentRule { keyword: "copilot",   display: "GitHub Copilot" },
    AgentRule { keyword: "cursor",    display: "Cursor" },
    AgentRule { keyword: "claude",    display: "Claude Code" },
    AgentRule { keyword: "windsurf",  display: "Windsurf" },
    AgentRule { keyword: "aider",     display: "Aider" },
    AgentRule { keyword: "amazonq",   display: "Amazon Q" },
    // Broad VS Code rule last — matches Code Helper, Code.app, etc.
    AgentRule { keyword: "code",      display: "VS Code" },
];

/// Match a process name against agent rules and return the display name; returns None if no rule matches.
pub fn identify(process_name: &str) -> Option<&'static str> {
    let lower = process_name.to_lowercase();
    RULES.iter()
        .find(|r| lower.contains(r.keyword))
        .map(|r| r.display)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_cursor() {
        assert_eq!(identify("Cursor"), Some("Cursor"));
        assert_eq!(identify("cursor Helper"), Some("Cursor"));
    }

    #[test]
    fn identifies_claude() {
        assert_eq!(identify("claude"), Some("Claude Code"));
    }

    #[test]
    fn identifies_opencode() {
        assert_eq!(identify("opencode"), Some("OpenCode"));
        // must NOT be misidentified as VS Code
        assert_ne!(identify("opencode"), Some("VS Code"));
    }

    #[test]
    fn identifies_copilot() {
        assert_eq!(identify("GitHub Copilot for Xcode Extension"), Some("GitHub Copilot"));
        assert_eq!(identify("copilot"), Some("GitHub Copilot"));
    }

    #[test]
    fn ignores_unknown() {
        assert_eq!(identify("Safari"), None);
        assert_eq!(identify("kernel_task"), None);
    }
}
