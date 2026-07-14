# attacker/hf_loader.py
# Fetch attack prompts from a HuggingFace dataset, optionally filtered by category.
#
# Produces the SAME attack-dict shape the rest of PromptXploit expects:
#   {"id", "category", "prompt", ...}
#
# Streams the dataset by default, so selecting one category (e.g. tool_abuse)
# with a limit only pulls what you need instead of downloading the whole set.
#
# Verified against:
#   neuralchemy/prompt-injection-Threat-Matrix  (subsets: binary, multiclass)
#       -> prompt col "text", category col "intent" (+ technique/severity/surface)
#   neuralchemy/Prompt-injection-dataset        (subsets: core, full)
#       -> prompt col "text", category col "category"

import itertools

from datasets import load_dataset

# Candidate column names, tried in order during auto-detection.
PROMPT_FIELDS = ["text", "prompt", "attack", "attack_prompt", "input", "payload", "instruction"]
CATEGORY_FIELDS = ["intent", "category", "type", "attack_type", "class", "subset"]
ID_FIELDS = ["id", "attack_id", "uid", "idx", "group_id"]

# Threat-Matrix extra dimensions worth carrying through when present.
EXTRA_FIELDS = ["technique", "severity", "surface", "source", "ambiguity", "tags"]


def _pick_field(columns, candidates, explicit=None):
    if explicit:
        if explicit not in columns:
            raise ValueError(f"field '{explicit}' not found in dataset columns {columns}")
        return explicit
    for c in candidates:
        if c in columns:
            return c
    return None


def _normalize_categories(category):
    """Accept 'tool_abuse', 'a,b,c', or ['a','b'] -> lowercase set, or None."""
    if not category:
        return None
    items = category if isinstance(category, list) else str(category).split(",")
    return {c.strip().lower() for c in items if c.strip()}


def load_attacks_from_hf(
    dataset_id,
    split="train",
    subset=None,
    category=None,
    prompt_field=None,
    category_field=None,
    limit=0,
    token=None,
    streaming=True,
):
    """Load and normalize attacks from a HuggingFace dataset.

    Args:
        dataset_id:  e.g. "neuralchemy/prompt-injection-Threat-Matrix"
        split:       dataset split (default "train")
        subset:      HF config/subset (e.g. "multiclass", "core")
        category:    keep only rows whose category matches (str, csv, or list)
        prompt_field/category_field: override auto-detection when needed
        limit:       cap number of attacks returned (0 = all matching)
        token:       HF token for private datasets
        streaming:   stream rows (default True) — efficient for filtered pulls

    Returns: list of {"id", "category", "prompt", "source", ...dims} dicts.
    """
    ds = load_dataset(dataset_id, subset, split=split, token=token, streaming=streaming)

    # Determine columns. Streaming datasets expose them lazily, so peek row 1.
    rows = ds
    if streaming:
        iterator = iter(ds)
        try:
            first = next(iterator)
        except StopIteration:
            return []
        columns = list(first.keys())
        rows = itertools.chain([first], iterator)
    else:
        columns = ds.column_names

    prompt_col = _pick_field(columns, PROMPT_FIELDS, prompt_field)
    if prompt_col is None:
        raise ValueError(
            f"Could not auto-detect a prompt column in {columns}. Pass --prompt-field."
        )
    category_col = _pick_field(columns, CATEGORY_FIELDS, category_field)
    id_col = _pick_field(columns, ID_FIELDS)

    wanted = _normalize_categories(category)
    if wanted and category_col is None and subset is None:
        raise ValueError(
            f"--category given but no category column in {columns} and no --subset. "
            f"Pass --category-field or --subset."
        )

    attacks = []
    for i, row in enumerate(rows):
        row_cat = (
            str(row.get(category_col)).lower()
            if category_col and row.get(category_col) is not None
            else (subset or "unknown")
        )
        if wanted and row_cat not in wanted:
            continue

        prompt = row.get(prompt_col)
        if not prompt or not str(prompt).strip():
            continue

        attack = {
            "id": str(row.get(id_col)) if id_col and row.get(id_col) is not None else f"HF-{i:05d}",
            "category": row_cat,
            "prompt": str(prompt),
            "source": f"hf:{dataset_id}" + (f":{subset}" if subset else ""),
        }
        # Carry through any Threat-Matrix dimensions that exist (handy for reports).
        for extra in EXTRA_FIELDS:
            if extra in columns and row.get(extra) is not None:
                attack[extra] = row.get(extra)
        attacks.append(attack)

        if limit and len(attacks) >= limit:
            break

    return attacks
