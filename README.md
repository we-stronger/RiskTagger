# RiskTagger

Research code for the WWW 2027 version of RiskTagger. The input is an externally
supplied case profile containing seed addresses and incident context.

```text
Tracer/                 # Fetch, translate, reason with memory, and expand the graph
Explainer/              # Evidence reports and optional paper evaluation
examples/               # Empty case-profile template; no experimental results
scripts/                # Release security scan and clean source export
tests/                  # Offline pipeline and release-security checks
project_settings.yaml   # Non-secret model, crawler, and tracing settings
.env.example            # Empty credential template
```

## Setup and input

Use Python 3.10 or later and install `pip install -r requirements.txt`. Copy
`.env.example` to `.env` and supply credentials locally. Existing environment
variables take precedence. Model names and public endpoints are configured in
`project_settings.yaml`.

The default settings follow Appendix B: a 0.05 ETH-equivalent dust threshold,
99% fund coverage, 100 downstream candidates per account, a 50-day time window,
16 parallel analysis workers, and LLM temperature 0.3. The default tracing budget
is 15 layers (indices 0–14); use `python -m Tracer --max-depth 20` for 20 layers.

Live crawling requires a separate BlockchainSpider checkout and its dependencies;
set `BLOCKCHAIN_SPIDER_DIR` to that checkout. This repository does not bundle it.

Set the event name in `project_settings.yaml`, or override it with
`RISKTAGGER_EVENT_NAME`. Place supplied inputs at:

```text
data/cases/<event>/case_profile.json          # See examples/case_profile.json
data/cases/<event>/source_addr_token/<event>_source_addr0.csv  # Optional seed CSV
data/reference_list/                        # exchange-list.csv, wallet-list.csv,
                                           # others-list.csv, hack-list.csv
```

The profile accepts `seed_addresses` and incident context. The legacy
`findings[].attacker_addresses` input format is also accepted. Seed CSVs have an
`address` column and an optional `parent_tx_time` column. Reference datasets and
private case data are supplied separately; local CSVs are retained outside Git.

## Run

```shell
python -m Tracer
python -m Explainer.evidence_explainer
```

Tracer writes to `outputs/tracer/<event>/`. Explainer consumes the saved Tracer
judgments, constructs statistics and evidence inputs, and writes to
`outputs/explainer/<event>/`. Use `--help` on the tracing or report-generation
entry point for input options.

Only High/Medium accounts are saved as positive (`label=1`) in
`data/RiskTagger_hack/accounts-hacker.csv` under the event's Tracer output.
Low and no-suspicion accounts are saved as negative (`label=0`) in
`data/all_data_normal/normal_addr_info.csv`; the `name_tag` retains the risk level.

## Optional report evaluation (paper Section 6.2.2)

The multi-agent scoring prompt and the 1–5 scoring rubric are provided in
`Explainer/multi_agent_evaluator.py`, in `MultiAgentEvaluator.build_evaluation_prompt`.
The dimensions are Accuracy, Logic, Professionalism, and Actionability, with a
separately assigned holistic Overall score. These scripts are separate from the
main tracing and report-generation commands.

```shell
python -m Explainer.multi_agent_evaluator
python -m Explainer.summary_scores
```

Configure the evaluator models in `project_settings.yaml` under
`modules.explainer.multi_agent.agents` and supply their keys only through the
local `.env` file or environment variables. Evaluation outputs are saved under
`outputs/explainer/<event>/evaluation/`; score summaries are exported as Excel.

## Check and export

```shell
python -m unittest discover -s tests -v
python scripts/check_release.py
python scripts/build_release.py
```

These commands also work before Git initialization. In an initialized repository,
`python scripts/check_release.py --staged` scans staged files and
`python scripts/check_release.py --history` also scans local Git history.

The export is `dist/RiskTagger_WWW2027_source.zip`. Extract it into a **new Git
repository** for publication: it excludes Git history, local credentials, data,
outputs, and the local paper PDF. A normal push of an existing repository also
publishes its reachable history; `.gitignore` does not remove historical secrets.
Revoke or rotate any credential that has previously entered Git history.

The scanner detects common credential formats, literal key assignments, private
files selected for Git, and copies of local `.env` credentials. It is a local
check, not a guarantee against every possible secret format. The offline tests
do not call paid model APIs or validate live blockchain services.
