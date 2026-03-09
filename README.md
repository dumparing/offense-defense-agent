# Offense-Defense Agent

An LLM-driven autonomous agent for **authorized defensive security testing**.

This research prototype uses a local Llama model (via Ollama) to plan
reconnaissance tasks, execute security tools, summarize findings, and
maintain structured memory across multi-step workflows — all without
sending data off-machine.

> **Warning:** This tool is for **authorized defensive testing only**.
> Only scan systems you have explicit permission to test.

## Architecture

```
User Task → Planner LLM → Skill Execution → Summarizer → Memory → Result
                ↑                                            │
                └────────── condensed context ────────────────┘
```

**Three layers:**
- **Agent Loop** — LLM-based planning, orchestration, and decision tracing
- **Skills** — High-level capabilities (network scan, etc.)
- **Tools** — Subprocess wrappers for external tools (nmap, etc.)

**Key features:**
- Local LLM planner (Llama 3 via Ollama) — no data leaves the machine
- Structured memory manager prevents context bloat across turns
- LLM-based output summarization and finding extraction
- Full decision trace for auditability
- Graceful fallback to keyword matching if Ollama is unavailable

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Project Structure

```
offense-defense-agent/
├── agent/
│   └── agent.py              # Core agent loop (plan → act → summarize → remember)
├── core/
│   ├── llm_client.py          # Ollama HTTP client for local Llama
│   ├── memory_manager.py      # Structured state store
│   ├── skill_base.py          # Abstract base class for all skills
│   ├── skill_registry.py      # Skill discovery & lookup
│   └── summarizer.py          # LLM-based output compression
├── skills/
│   └── network_scan.py        # Network scan skill (nmap -sV)
├── tools/
│   └── nmap_runner.py         # Safe subprocess wrapper for nmap
├── examples/
│   ├── run_scan.py            # Single-turn demo
│   └── demo_agent_session.py  # Multi-turn demo with shared memory
├── ARCHITECTURE.md            # Detailed design documentation
└── README.md                  # This file
```

## Requirements

- **Python 3.10+**
- **nmap** — network scanner
- **Ollama** — local LLM runtime

No external Python packages required (uses only the standard library).

## Setup

### 1. Install nmap

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap
```

### 2. Install Ollama

Download from [ollama.com](https://ollama.com/) or:

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh
```

### 3. Start Ollama and pull a model

```bash
# Start the Ollama server (runs on http://localhost:11434)
ollama serve

# In another terminal, pull the Llama 3 8B model
ollama pull llama3:8b
```

### 4. (Optional) Configure the model

The default model is `llama3:8b`. Override with an environment variable:

```bash
export OLLAMA_MODEL=llama3:8b        # default
export OLLAMA_MODEL=mistral:7b       # alternative
export OLLAMA_MODEL=llama3:70b       # larger model if you have the RAM
```

## Usage

### Single-turn scan

```bash
# Scan localhost (default)
python examples/run_scan.py

# Scan a specific authorized target
python examples/run_scan.py 192.168.1.10
```

Output includes:
- **Planner decision** — which skill was chosen and why
- **Summarized findings** — LLM-compressed natural language summary
- **Structured data** — extracted ports, services, and findings
- **Memory snapshot** — the agent's current state
- **Decision trace** — step-by-step audit log

### Multi-turn session

```bash
python examples/demo_agent_session.py
python examples/demo_agent_session.py 192.168.1.10
```

Demonstrates two sequential turns with shared memory:
1. "Scan the target machine for open services"
2. "Summarize the most important findings so far"

The second turn uses the memory snapshot from turn 1 instead of
re-running the scan, showing how context stays compact.

## How It Works

### Planning (LLM-based)

Each turn, the planner receives the task, skill catalog, and memory snapshot.
It returns a JSON plan:

```json
{
  "skill": "network_scan",
  "arguments": {"target_ip": "127.0.0.1"},
  "reasoning_summary": "Task requests reconnaissance; network_scan fits best."
}
```

If Ollama is down, the agent falls back to keyword matching — the demo
always works.

### Memory Management

The `MemoryManager` stores structured findings across turns:
- Target IP, open ports, service mappings
- Key findings (short factual sentences)
- Action history (which skills ran, with what result)
- Condensed history (LLM-generated step summaries)

The planner reads a compact snapshot each turn instead of raw tool output,
preventing context window bloat.

### Summarization

After each skill execution, the `Summarizer` uses the local LLM to compress
raw output into:
- A natural-language summary
- Structured findings (ports, services, observations)

The summarizer **never fabricates vulnerabilities** not present in the data.
It falls back to rule-based extraction if the LLM is unavailable.

### Privacy

All inference runs locally via Ollama. No scan data, findings, or prompts
leave the machine. This is critical for security-sensitive assessments.

## Safety

- IP addresses are validated before any subprocess call (prevents injection)
- Subprocess arguments are passed as lists (no `shell=True`)
- All tool calls have timeouts (120s default)
- The agent only performs reconnaissance, not exploitation
- Every decision is traced for auditability
- Authorization warnings are displayed at startup
