# Architecture — LLM-Driven Security Testing Agent

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        USER                                 │
│             "Scan the target for open services"             │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    AGENT LOOP                               │
│                  (agent/agent.py)                            │
│                                                             │
│   ┌──────────┐   ┌──────────┐   ┌───────────┐              │
│   │ PLANNER  │──▶│   ACT    │──▶│ SUMMARIZE │──┐           │
│   │ (LLM)    │   │          │   │ (LLM)     │  │           │
│   │          │   │ Execute  │   │ Compress   │  │           │
│   │ Select   │   │ skill    │   │ results    │  │           │
│   │ skill    │   │          │   │            │  │           │
│   └──────────┘   └──────────┘   └───────────┘  │           │
│        ▲                                        │           │
│        │         ┌───────────┐                  │           │
│        │         │  MEMORY   │◀─────────────────┘           │
│        └─────────│  MANAGER  │                              │
│                  │           │                              │
│                  │ Structured│                              │
│                  │ state     │                              │
│                  └───────────┘                              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    SKILLS LAYER                             │
│                  (skills/*.py)                               │
│                                                             │
│   ┌────────────────┐  ┌────────────────┐  ┌──────────────┐ │
│   │ network_scan   │  │ sql_injection  │  │  exploit     │ │
│   │                │  │  (future)      │  │  (future)    │ │
│   └───────┬────────┘  └────────────────┘  └──────────────┘ │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                   TOOL CONNECTORS                           │
│                   (tools/*.py)                               │
│                                                             │
│   ┌────────────────┐  ┌────────────────┐  ┌──────────────┐ │
│   │ nmap_runner    │  │ sqlmap_runner  │  │  msf_runner  │ │
│   │                │  │  (future)      │  │  (future)    │ │
│   └───────┬────────┘  └────────────────┘  └──────────────┘ │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                  EXTERNAL TOOLS                             │
│          Nmap        SQLMap       Metasploit       Burp     │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### Planner (LLM-Based Skill Selection)

**File:** `agent/agent.py` → `SecurityAgent._plan()`

The planner replaces the old keyword-matching heuristic with a local Llama
model running via Ollama. Each turn, the planner receives:

- The user's natural-language task
- The full skill catalog (names, descriptions, input schemas)
- The current memory snapshot (what has already been discovered)

It returns strict JSON:
```json
{
  "skill": "network_scan",
  "arguments": {"target_ip": "127.0.0.1"},
  "reasoning_summary": "Task requests service discovery; network_scan is the best fit."
}
```

**Fallback:** If Ollama is unavailable, the agent falls back to keyword matching
so the demo always works.

### Skills Layer

**Base class:** `core/skill_base.py` → `SkillBase`
**Registry:** `core/skill_registry.py` → `SkillRegistry`
**Implementations:** `skills/*.py`

Every skill implements a uniform interface:
- `name` — unique identifier
- `description` — one-line summary for the planner
- `input_schema` — required parameters and types
- `execute(**kwargs)` — run the skill, return `{success, data, error}`

The registry decouples skill discovery from the agent loop. Adding new skills
requires zero changes to the agent.

### Tool Connectors

**Files:** `tools/*.py`

Thin wrappers around external security tools (nmap, etc.). They handle:
- Input validation (IP address validation prevents command injection)
- Subprocess execution with timeouts
- Output parsing into structured dicts

### Memory Manager

**File:** `core/memory_manager.py` → `MemoryManager`

Structured state store that persists across agent turns. Tracks:

| Field | Purpose |
|-------|---------|
| `current_target` | IP being assessed |
| `discovered_open_ports` | Deduplicated list of open ports |
| `discovered_services` | Port→service mapping |
| `findings` | High-level observation sentences |
| `attempted_actions` | Log of skills executed and their outcomes |
| `condensed_history` | LLM-generated summaries of past steps |

The planner reads `get_context_snapshot()` each turn instead of raw tool output.
This prevents context window bloat in multi-step workflows.

### Summarizer

**File:** `core/summarizer.py` → `Summarizer`

After each skill execution, the summarizer uses the local LLM to compress
raw tool output into:

1. A concise natural-language summary
2. Structured findings (ports, services, observations)

The summarizer **must not fabricate vulnerabilities** not present in the data.
It falls back to rule-based extraction if the LLM is unavailable.

### Why Local Llama?

| Benefit | Explanation |
|---------|-------------|
| **Privacy** | Security scan data never leaves the machine |
| **No API keys** | No billing, no rate limits, no external dependencies |
| **Reproducibility** | Same model version = same behavior |
| **Compliance** | Sensitive assessment data stays on-premise |
| **Speed** | No network latency for inference |

## Directory Layout

```
offense-defense-agent/
├── agent/
│   └── agent.py              # Agent loop: plan → act → summarize → remember
├── core/
│   ├── llm_client.py          # Ollama HTTP client for local Llama
│   ├── memory_manager.py      # Structured state store
│   ├── skill_base.py          # Abstract base class for skills
│   ├── skill_registry.py      # Skill discovery & lookup
│   └── summarizer.py          # LLM-based output compression
├── skills/
│   └── network_scan.py        # Nmap service scan skill
├── tools/
│   └── nmap_runner.py         # Subprocess wrapper for nmap
├── examples/
│   ├── run_scan.py            # Single-turn demo
│   └── demo_agent_session.py  # Multi-turn demo with memory
├── ARCHITECTURE.md            # This file
└── README.md                  # Setup and usage guide
```

## Data Flow (Single Turn)

```
1. User provides task:      "Scan the target for open services"
                                    │
2. Memory snapshot read:   ────────▶ {} (empty on first turn)
                                    │
3. Planner LLM decides:   ────────▶ {"skill": "network_scan",
                                    │   "arguments": {"target_ip": "127.0.0.1"}}
                                    │
4. Skill executes:         ────────▶ NetworkScanSkill → nmap_runner
                                    │
5. Summarizer compresses:  ────────▶ "Found 3 open services..."
                                    │   + structured: {open_ports, services, findings}
                                    │
6. Memory updated:         ────────▶ {target, ports, services, findings, history}
                                    │
7. Result returned:        ────────▶ summary + structured + memory + trace
```

## Multi-Turn Memory Flow

```
Turn 1: "Scan for open services"
    → Planner sees empty memory → selects network_scan
    → Memory now has: ports=[22,80], services={22:ssh, 80:http}

Turn 2: "Summarize findings so far"
    → Planner sees populated memory → can summarize without re-scanning
    → Memory grows with condensed_history entry
```

## Extending the System

To add a new skill (e.g. vulnerability scanning):

1. **Create tool wrapper:** `tools/openvas_runner.py`
2. **Create skill class:** `skills/vuln_scan.py` (inherits `SkillBase`)
3. **Register at startup:** `registry.register(VulnScanSkill())`
4. **(Optional)** Add keywords to `KEYWORD_SKILL_MAP` for fallback mode

The planner LLM discovers new skills automatically from the registry's
`list_skills()` metadata — no prompt changes needed.
