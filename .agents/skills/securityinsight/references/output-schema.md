# Security Insight Output Format

The final output of the `securityinsight` skill must be exactly one human-readable Markdown report.

## Required Report Template

Use this structure and keep the section order stable:

```md
# Security Verdict

- Status: completed|insufficient_evidence|error
- Analysis Type: prompt|threat
- Threat Level: <score> (<label>, scale 0-4)
- Threat Type: none|prompt_injection|data_exfiltration|code_execution|privilege_escalation|resource_abuse|information_disclosure|other
- Confidence: 0.00-1.00

## Summary

One short, high-signal conclusion.

## Key Evidence

1. [severity] source - title
   Concise supporting evidence.
2. [severity] source - title
   Concise supporting evidence.

## Interpretation

A concise narrative paragraph that states the security consequence of the observed behavior, then naturally incorporates any mitigating or aggravating factors that justify the chosen threat level and confidence.

## Recommendations

- Actionable follow-up step.
- Actionable follow-up step.
```

## Field Guidance

### `Status`

Allowed values:

- `completed`
- `insufficient_evidence`
- `error`

Use:

- `completed` when the collected package supports a real judgment
- `insufficient_evidence` when the package is too incomplete or ambiguous
- `error` only when the analysis itself cannot be completed

### `Analysis Type`

Allowed values:

- `prompt`
- `threat`

Must match the kind of evidence package produced by the CLI.

### `Threat Level`

Integer severity level with explicit label and range.

Output format:

- `<score> (<label>, scale 0-4)`
- Example: `1 (low, scale 0-4)`

Recommended interpretation:

- `0 (none)`: no meaningful security concern
- `1 (low)`: low concern
- `2 (medium)`: medium concern
- `3 (high)`: high concern
- `4 (critical)`: critical concern

### `Threat Type`

Use the closest matching category:

- `none`
- `prompt_injection`
- `data_exfiltration`
- `code_execution`
- `privilege_escalation`
- `resource_abuse`
- `information_disclosure`
- `other`

### `Confidence`

Float in `[0.0, 1.0]`.

Lower confidence when:

- evidence is incomplete
- multiple interpretations remain plausible
- the CLI notes significant truncation

### `Summary`

Short, high-signal conclusion.

Requirements:

- concise
- no unsupported claims
- shorter than `Interpretation`

### `Key Evidence`

List concrete supporting items.

Each entry should point to one observed fact from the collected package and use this shape:

```md
1. [high] security_event - Outbound request to unknown host
   Runner output shows a request to `example.invalid` immediately after prompt override.
```

Rules:

- Keep each item factual and atomic.
- Describe what was observed, not what it means.
- Do not restate the final judgment here.
- Avoid combining multiple observations into one bullet unless the CLI reports them as one event.
- Prefer one evidence item per observation, even if several items support the same conclusion.

Allowed `source` values:

- `scan_overview`
- `detail_event`
- `telemetry`
- `runner_output`
- `prompt_candidate`
- `process_tree`

Allowed `severity` values:

- `info`
- `low`
- `medium`
- `high`
- `critical`

### `Interpretation`

A single narrative paragraph (or two at most) that explains the security consequence of the observed behavior.

Structure the narrative as:

1. **State the consequence** — what could go wrong or already went wrong, grounded in evidence.
2. **Weave in factors that raise or lower severity** — e.g., "however, all outbound traffic stayed within the official API endpoint" or "this is compounded by the fact that credentials were read immediately before the POST."
3. **Acknowledge evidence gaps that affect confidence** — e.g., "payload contents were not captured, so actual data exposure cannot be confirmed."

These three elements should flow as connected prose, not as separate bullet lists or subsections.

Requirements:

- every claim must trace to at least one Key Evidence item
- do not repeat evidence bullets verbatim; synthesize and explain their combined meaning
- the paragraph should make the Threat Level and Confidence values feel self-evident to the reader

Avoid:

- sub-headings inside Interpretation
- bullet-list-only Interpretation sections
- hedging so heavily that the reader cannot determine whether the finding is serious

### `Recommendations`

Flat list of actionable follow-up steps.

Good examples:

- isolate the affected execution
- inspect outbound network activity for the selected window
- review the referenced prompt candidate payloads

## Validation Rules

Before finalizing:

1. Ensure the output is a single Markdown report, not JSON.
2. Ensure each claim in `Interpretation` is supported by at least one item in `Key Evidence`.
3. Ensure `Threat Type`, `Threat Level`, and `Confidence` are consistent.
4. Ensure `Summary` does not introduce claims missing from `Interpretation`.
5. Evidence sources should trace back to specific scan overview data or detail events.
