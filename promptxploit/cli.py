# main.py
# PromptXploit — LLM Pentesting Tool (CLI)
#
# Two ways to source attacks:
#   local  — the JSON files bundled under attacks/  (simple, offline, the classic mode)
#   hf     — stream from a HuggingFace dataset, filter by category, cap the count
#
# Pace the run with --rate (attacks per minute) so you don't hammer an endpoint.

import argparse
import importlib.util
import json
import os
import time
import sys

from .attacker.loader import load_attacks
from .attacker.hf_loader import load_attacks_from_hf
from .attacker.rate_limiter import RateLimiter
from .evaluator.rules import apply_rules
from .evaluator.judge import judge_batch  # unified judge: local (Ollama) / openai / gemini / none
from .scoring.risk import compute_risk

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn


# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

JUDGE_BATCH_SIZE = 10
JUDGE_INTERVAL = 10  # seconds between judge API calls (separate from attack rate)

console = Console()

timing = {"start": 0.0, "end": 0.0, "attacks": 0, "target_time": 0.0, "judge_time": 0.0}


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def load_target(path):
    path = os.path.abspath(path)
    spec = importlib.util.spec_from_file_location("promptxploit_target", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load target module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "run"):
        raise RuntimeError("Target must define run(prompt: str)")
    return module.run


def load_attack_set(args):
    """Route attack loading to local files or a HuggingFace dataset."""
    if args.source == "hf":
        if not args.dataset:
            raise SystemExit("--dataset is required when --source hf")
        console.print(
            f"[bold]Fetching from HF:[/bold] {args.dataset}"
            + (f" [{args.subset}]" if args.subset else "")
            + (f"  category={args.category}" if args.category else "")
        )
        return load_attacks_from_hf(
            dataset_id=args.dataset,
            split=args.split,
            subset=args.subset,
            category=args.category,
            prompt_field=args.prompt_field,
            category_field=args.category_field,
            limit=args.limit,
            token=args.hf_token or os.environ.get("HF_TOKEN"),
        )
    # local
    attacks = load_attacks(args.attacks)
    if args.category:
        wanted = {c.strip().lower() for c in args.category.split(",")}
        attacks = [a for a in attacks if str(a.get("category", "")).lower() in wanted]
    if args.limit:
        attacks = attacks[: args.limit]
    return attacks


def print_attack_result(attack_id, category, verdict, risk):
    color = {"pass": "green", "partial": "yellow", "fail": "red"}.get(verdict["verdict"], "white")
    console.print(
        f"[bold]{attack_id}[/bold] {category:<22} → "
        f"[{color}]{verdict['verdict'].upper():<7}[/{color}] ({risk['risk_level']})"
    )


def print_summary(report):
    console.print("\n[bold cyan]=== Scan Summary ===[/bold cyan]")
    console.print(f"Total attacks: {len(report)}")
    console.print(f"Fails: {sum(r['verdict']['verdict'] == 'fail' for r in report)}")
    console.print(f"Partials: {sum(r['verdict']['verdict'] == 'partial' for r in report)}")
    console.print(f"Passes: {sum(r['verdict']['verdict'] == 'pass' for r in report)}")


def print_timing():
    total = timing["end"] - timing["start"]
    console.print("\n[bold cyan]=== Timing ===[/bold cyan]")
    console.print(f"Total scan time: {total:.2f}s")
    if timing["attacks"]:
        console.print(f"Avg model time: {timing['target_time'] / timing['attacks']:.2f}s")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PromptXploit — LLM Pentesting Tool")
    parser.add_argument("--target", required=True, help="Path to target module (defines run(prompt))")
    parser.add_argument("--output", required=True, help="Output JSON file")

    # attack source (HuggingFace by default — pulls the curated, categorized set)
    parser.add_argument("--source", choices=["local", "hf"], default="hf",
                        help="Where to get attacks: a HuggingFace dataset (default) or local files")
    parser.add_argument("--attacks", default="attacks", help="[local] attacks directory")
    parser.add_argument("--dataset", default="neuralchemy/prompt-injection-dataset-categorized",
                        help="[hf] dataset id (default: the categorized intent dataset)")
    parser.add_argument("--subset", default="intent",
                        help="[hf] dataset subset/config (default: intent; also technique/severity/surface/…)")
    parser.add_argument("--split", default="train", help="[hf] dataset split (default train)")
    parser.add_argument("--prompt-field", dest="prompt_field", help="[hf] override prompt column")
    parser.add_argument("--category-field", dest="category_field", help="[hf] override category column")
    parser.add_argument("--hf-token", dest="hf_token", help="[hf] token for private datasets (or set HF_TOKEN)")

    # filtering + pacing (apply to both sources)
    parser.add_argument("--category", help="only use this category/intent (comma-separated for several)")
    parser.add_argument("--limit", type=int, default=0, help="max number of attacks (0 = all)")
    parser.add_argument("--rate", type=float, default=0,
                        help="max attacks per minute against the target (0 = unlimited)")

    # judge for cases the deterministic rules can't decide
    parser.add_argument("--judge", choices=["local", "openai", "gemini", "none"], default="local",
                        help="judge backend for uncertain cases (default: local Ollama — nothing leaves your machine)")
    parser.add_argument("--judge-model", dest="judge_model", default="llama3.1:8b",
                        help="model for --judge local (Ollama) or the API model name")
    parser.add_argument("--ollama-url", dest="ollama_url", default="http://localhost:11434",
                        help="Ollama endpoint for --judge local")

    args = parser.parse_args()

    console.print("\n[bold cyan]PromptXploit starting...[/bold cyan]\n")
    timing["start"] = time.perf_counter()

    with Progress(SpinnerColumn(), TextColumn("Loading target…"), console=console):
        run_target = load_target(args.target)
    console.print("[green]✔ Target loaded[/green]\n")

    attacks = load_attack_set(args)
    console.print(f"[bold]Loaded {len(attacks)} attacks[/bold]\n")
    if not attacks:
        console.print("[yellow]No attacks matched — check --category / --subset.[/yellow]")
        sys.exit(1)

    limiter = RateLimiter(max_per_minute=args.rate)
    if args.rate:
        console.print(f"[dim]Rate limited to {args.rate} attacks/min[/dim]\n")

    report = []
    uncertain = []  # cases the rules can't decide — judged in pass 2

    # ── Pass 1: attack the target, apply the deterministic rules ──
    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"), console=console) as progress:
        task = progress.add_task("Attacking target…", total=len(attacks))
        for attack in attacks:
            progress.update(task, description=f"{attack['id']} ({attack['category']})")
            limiter.wait()  # pace against the target endpoint

            t0 = time.perf_counter()
            response = run_target(attack["prompt"])
            timing["target_time"] += (time.perf_counter() - t0)
            timing["attacks"] += 1

            verdict = apply_rules(attack["prompt"], response)  # None if rules can't decide
            entry = {
                "attack_id": attack["id"],
                "category": attack["category"],
                "source": attack.get("source", args.source),
                "verdict": verdict,
                "risk": None,
            }
            report.append(entry)
            if verdict is None:
                uncertain.append({"id": attack["id"], "attack_prompt": attack["prompt"],
                                  "model_response": response, "_entry": entry})
            progress.advance(task)

    # ── Pass 2: judge only the uncertain cases with the chosen backend ──
    if uncertain and args.judge != "none":
        console.print(
            f"\n[dim]Judging {len(uncertain)} uncertain case(s) via '{args.judge}'"
            f"{' (' + args.judge_model + ')' if args.judge != 'none' else ''}…[/dim]"
        )
        by_id = {u["id"]: u["_entry"] for u in uncertain}
        # local judging is free/offline -> one big pass; API backends -> chunked.
        chunk = len(uncertain) if args.judge == "local" else JUDGE_BATCH_SIZE
        for i in range(0, len(uncertain), chunk):
            group = uncertain[i:i + chunk]
            t4 = time.perf_counter()
            verdicts = judge_batch(
                [{"id": g["id"], "attack_prompt": g["attack_prompt"],
                  "model_response": g["model_response"]} for g in group],
                backend=args.judge, model=args.judge_model, api_base=args.ollama_url,
            )
            timing["judge_time"] += (time.perf_counter() - t4)
            for cid, v in verdicts.items():
                if cid in by_id:
                    by_id[cid]["verdict"] = v
            if args.judge in ("openai", "gemini") and i + chunk < len(uncertain):
                time.sleep(JUDGE_INTERVAL)  # pace paid API calls

    # ── Finalize: fill any still-unjudged verdicts, compute risk, print ──
    for entry in report:
        if entry["verdict"] is None:
            entry["verdict"] = {"verdict": "partial", "confidence": 0.0, "severity": 0.0,
                                "rationale": "rules_only" if args.judge == "none" else "unjudged"}
        entry["risk"] = compute_risk(entry["verdict"])
        print_attack_result(entry["attack_id"], entry["category"], entry["verdict"], entry["risk"])

    timing["end"] = time.perf_counter()

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print_summary(report)
    print_timing()
    console.print(f"\n[green bold]✔ Scan complete[/green bold] → {args.output}\n")


if __name__ == "__main__":
    main()
