# Part 4 Risk Engine Compatibility Path

This historical directory name contains legacy command-line examples and test
fixtures. Its `risk_engine.py` now re-exports the canonical implementation in
[`../risk_engine/`](../risk_engine/). New code should import
`chem_shield_p4.risk_engine.RiskEngine`.

The preserved formula, thresholds, score semantics, HMI endpoints, and test
commands are documented in
[`../correlation/README.md`](../correlation/README.md).

Run the legacy tests from the repository root:

```bash
chem_shield_p1/.venv/bin/python -m unittest discover \
  -s 'chem_shield_p4/risk engin/tests' -v
```
