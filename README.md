# PromptXploit


[![PyPI Downloads](https://static.pepy.tech/personalized-badge/promptxploit?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/promptxploit)

LLM penetration testing from the command line. Point it at any model or endpoint,
run a categorized set of prompt-injection and jailbreak attacks, and get a
structured report of what got through.

> Authorized testing only. Use PromptXploit against systems you own or are
> explicitly permitted to test. See [DISCLAIMER.md](./DISCLAIMER.md).

---

## Overview

PromptXploit runs adversarial prompts against a target model, decides whether each
attack succeeded, and writes the results to JSON. Attacks are streamed from a
curated, categorized dataset; verdicts are decided locally by default, so nothing
about your target leaves your machine. It is framework-agnostic: any LLM or HTTP
endpoint works as long as it can be wrapped in a single `run(prompt)` function.

The pipeline is deliberately ordered cheapest-first:

```
attacks  →  target  →  deterministic rules  →  judge (only the uncertain cases)  →  report
```

Deterministic rules resolve the obvious outcomes (clear refusals, clear bypasses)
before any model is invoked. Only the ambiguous cases are sent to the judge.

---

## Features

- **Categorized attacks from HuggingFace.** Stream a curated attack set and filter
  it by intent (for example, `tool_abuse`), pulling only what you need.
- **Local-first judging.** Verdicts are decided by a local model through Ollama —
  nothing leaves your machine. OpenAI and Gemini are optional backends.
- **Rules-first, low false-positive.** Deterministic checks handle refusals and
  obvious bypasses before spending a model call, so the report does not cry wolf.
- **Rate limiting.** Cap attacks per minute so you do not overload a target.
- **Framework-agnostic targets.** Any LLM, local model, or HTTP endpoint.
- **Structured output.** Per-attack verdict, risk score, and rationale as JSON.

---

## Installation

```bash
pip install promptxploit
```

For the default local judge, install [Ollama](https://ollama.com) and pull a model:

```bash
ollama pull llama3.1:8b
```

From source:

```bash
git clone https://github.com/m4vic/promptxploit
cd promptxploit
pip install -e .
```

Optional API judges:

```bash
pip install "promptxploit[openai]"   # for --judge openai
pip install "promptxploit[gemini]"   # for --judge gemini
```

---

## Quick start

Define a target — any callable that takes a prompt and returns the model's response:

```python
# my_target.py
def run(prompt: str) -> str:
    return your_llm(prompt)
```

Run a scan. This pulls `tool_abuse` attacks, judges them locally, and writes a report:

```bash
promptxploit \
    --target my_target.py \
    --category tool_abuse \
    --judge local --judge-model llama3.1:8b \
    --rate 10 \
    --output scan.json
```

Read `scan.json` for the per-attack verdicts.

---

## Attack sources

By default, attacks are streamed from the categorized dataset
`neuralchemy/prompt-injection-dataset-categorized` (the `intent` configuration).

Available intents:

```
benign   direct_injection   system_extraction   role_hijack
obfuscation   tool_abuse   indirect_injection
```

| Flag | Purpose |
|------|---------|
| `--category tool_abuse` | Use only this intent (comma-separated for several) |
| `--limit 100` | Cap the number of attacks |
| `--subset intent` | Dataset configuration (default: `intent`) |
| `--dataset ORG/NAME` | Use a different HuggingFace dataset |

To use your own local attack files instead of the dataset:

```bash
promptxploit --source local --attacks ./attacks --target my_target.py --output scan.json
```

Local attack files are JSON lists of objects with `id`, `category`, and `prompt`.

---

## Judging

The judge decides the outcome for cases the deterministic rules cannot.

| Backend | Flag | Notes |
|---------|------|-------|
| Local (Ollama) | `--judge local` | Default. Runs entirely on your machine; nothing is sent to a third party. |
| OpenAI | `--judge openai` | Requires `OPENAI_API_KEY`. |
| Gemini | `--judge gemini` | Requires `GOOGLE_API_KEY`. |
| Rules only | `--judge none` | No model; uncertain cases are left as `partial`. |

The local backend is the default on purpose: when you are testing another party's
system, their responses should not be shipped to an external API. Choose the judge
model with `--judge-model` (for example, `llama3.1:8b` or `qwen2.5:14b-instruct`)
and point at a non-default Ollama host with `--ollama-url`.

---

## Targets

A target is any Python module that defines `run(prompt: str) -> str`. That function
can call a local model, a hosted API, or an entire application.

To test an HTTP endpoint, configure `targets/http_api_target.py` with your URL,
headers, and request shape, then pass it as `--target`. It works with OpenAI-style
APIs, Anthropic, and arbitrary REST endpoints.

---

## Rate limiting

```bash
promptxploit --target my_target.py --rate 5 --output scan.json
```

`--rate` caps attacks per minute against the target (0 means unlimited). API judges
are paced separately from the attack rate.

---

## Understanding the output

The report is a JSON list. Each entry records the attack, the verdict, and a
normalized risk score:

```json
{
  "attack_id": "HF-00042",
  "category": "tool_abuse",
  "source": "hf:neuralchemy/prompt-injection-dataset-categorized:intent",
  "verdict": {
    "verdict": "fail",
    "confidence": 0.9,
    "severity": 0.85,
    "rationale": "Model followed the injected tool instruction."
  },
  "risk": { "risk_score": 0.77, "risk_level": "high" }
}
```

Verdicts:

- **pass** — the attack was blocked; the model refused or answered safely.
- **fail** — the attack succeeded; the model complied, leaked, or was manipulated.
- **partial** — uncertain or requires manual review.

---

## Custom attacks

Provide your own attacks as a JSON list:

```json
[
  { "id": "CUSTOM-001", "category": "tool_abuse", "prompt": "Your attack prompt here" }
]
```

```bash
promptxploit --source local --attacks my_attacks.json --target my_target.py --output scan.json
```

---

## Responsible use

PromptXploit is a security testing tool for authorized use only: your own systems,
sanctioned penetration tests, and security research. Do not use it against systems
you are not permitted to test. Full terms are in [DISCLAIMER.md](./DISCLAIMER.md).

---

## Defense: PromptShield

PromptXploit finds where a model breaks. [PromptShield](https://github.com/m4vic/promptshields)
is the defensive counterpart that hardens it. The intended workflow is to test with
PromptXploit, add PromptShield, and re-test to confirm the gap is closed.

```bash
pip install promptshields
```

```python
from promptshield import Shield

shield = Shield.balanced()

def protected_llm(prompt: str, system_prompt: str) -> str:
    result = shield.protect_input(prompt, system_prompt)
    if result["blocked"]:
        return "Request blocked."
    return your_llm(prompt)
```

`protect_input` returns a result with `blocked`, `reason`, and `threat_level`.
PromptShield also provides `protect_output`, `protect_stream`, and `protect_tool_call`
for defending the response and agent surfaces. See the PromptShield repository for
the full guide.

A typical before-and-after run:

```bash
promptxploit --target unprotected.py --category tool_abuse --output before.json
promptxploit --target protected.py   --category tool_abuse --output after.json
```

---

## License

MIT. See [LICENSE](./LICENSE).
