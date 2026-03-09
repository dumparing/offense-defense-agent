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
│   │  REASON  │──▶│   ACT    │──▶│  OBSERVE  │──┐           │
│   │          │   │          │   │           │  │           │
│   │ Select   │   │ Execute  │   │ Summarize │  │           │
│   │ skill    │   │ skill    │   │ results   │  │           │
│   └──────────┘   └──────────┘   └───────────┘  │           │
│        ▲                                        │           │
│        └────────── loop if needed ──────────────┘           │
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
│                                                             │
│          Nmap        SQLMap       Metasploit       Burp     │
└─────────────────────────────────────────────────────────────┘
```

## Directory Layout

```
offense-defense-project/
├── agent/
│   └── agent.py            # Agent loop: reason → act → observe
├── core/
│   ├── skill_base.py       # Abstract base class for all skills
│   └── skill_registry.py   # Central skill discovery & lookup
├── skills/
│   └── network_scan.py     # First skill: Nmap service scan
├── tools/
│   └── nmap_runner.py      # Subprocess wrapper for nmap CLI
├── examples/
│   └── run_scan.py         # Runnable demo script
└── ARCHITECTURE.md         # This file
```

## Data Flow (network_scan example)

```
1. User provides task:  "Scan the target machine for open services"
                                    │
2. Agent matches keywords ──────────▶ selects "network_scan" skill
                                    │
3. Agent extracts params ───────────▶ {"target_ip": "127.0.0.1"}
                                    │
4. Skill calls tool wrapper ────────▶ nmap_runner.run_nmap_service_scan()
                                    │
5. Tool wrapper runs subprocess ────▶ `nmap -sV 127.0.0.1`
                                    │
6. Raw output parsed ──────────────▶ [{"port": 22, "service": "ssh", ...}]
                                    │
7. Agent summarizes ───────────────▶ "Found 3 open services on 127.0.0.1"
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Skills as classes with a base interface | Enables uniform discovery and invocation by the agent |
| Separate tools/ from skills/ | Tools are reusable wrappers; skills compose tools with logic |
| Keyword matching (not LLM) for skill selection | Keeps the prototype runnable without API keys |
| IP validation before subprocess call | Prevents command injection |
| Decision trace logging | Makes agent reasoning transparent for debugging and grading |

## Extending the System

To add a new skill (e.g. SQL injection testing):

1. Create `tools/sqlmap_runner.py` — subprocess wrapper for sqlmap
2. Create `skills/sql_injection.py` — inherits from `SkillBase`
3. Add keywords to `KEYWORD_SKILL_MAP` in `agent/agent.py`
4. Register the skill in `examples/run_scan.py` (or a new example script)

No changes to the agent loop or core framework required.
