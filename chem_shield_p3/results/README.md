# Part 3 results

Files without the `hard_scenario_` prefix are the current evaluation of the
checked-in 200-sample baseline input. Regenerate them with
`python3 -m chem_shield_p3.scripts.evaluate_model`. The previously reported
97% accuracy / 4% FPR are retained separately in
`historical_headline_metrics.csv`; they are historical synthetic figures, not
the refreshed model results or evidence of real-plant performance.

The `hard_scenario_` reports use the expanded, fixed-seed test set. Recreate
the input and reports from the repository root:

```bash
python3 -m chem_shield_p3.scripts.generate_test_scenarios \
  --seed 2026 --output chem_shield_p3/data/test_scenarios_harder.csv
python3 -m chem_shield_p3.scripts.evaluate_model \
  --input chem_shield_p3/data/test_scenarios_harder.csv \
  --predictions-output chem_shield_p3/results/hard_scenario_predictions.csv \
  --metrics-output chem_shield_p3/results/hard_scenario_evaluation_results.csv \
  --confusion-output chem_shield_p3/results/hard_scenario_confusion_matrix.csv \
  --scenario-output chem_shield_p3/results/hard_scenario_evaluation.csv \
  --latency-output chem_shield_p3/results/hard_scenario_detection_latency.csv \
  --latency-summary-output chem_shield_p3/results/hard_scenario_detection_latency_summary.csv \
  --errors-output chem_shield_p3/results/hard_scenario_ml_errors.csv
```

| File | Producer / contents |
| --- | --- |
| `physical_ml_output.csv` | `evaluate_model.py` predictions for the retained baseline; `run_detection.py` can also write this path for standalone inference. |
| `evaluation_results.csv` | `evaluate_model.py` aggregate baseline accuracy, precision, recall, F1, FPR, and counts. |
| `confusion_matrix.csv` | `evaluate_model.py` baseline actual/predicted counts. |
| `scenario_evaluation.csv` | `evaluate_model.py` baseline metrics by scenario type. |
| `detection_latency.csv` | `evaluate_model.py` baseline first-detection delays by anomalous scenario, in samples. |
| `detection_latency_summary.csv` | `evaluate_model.py` baseline detected/missed scenario totals and delay summary, in samples. |
| `ml_errors.csv` | `evaluate_model.py` baseline false-positive and false-negative rows; `analyze_ml_errors.py` reads this file. |
| `historical_headline_metrics.csv` | Preserved 200-sample headline metrics as originally reported; not regenerated because they are historical published figures. |
| `hard_scenario_predictions.csv` | Expanded evaluation predictions. |
| `hard_scenario_evaluation_results.csv` | Expanded evaluation aggregate metrics and counts. |
| `hard_scenario_confusion_matrix.csv` | Expanded evaluation actual/predicted counts. |
| `hard_scenario_evaluation.csv` | Expanded metrics by scenario type. |
| `hard_scenario_detection_latency.csv` | Expanded first-detection delays by anomalous scenario, in samples. |
| `hard_scenario_detection_latency_summary.csv` | Expanded detected/missed scenario totals and delay summary, in samples. |
| `hard_scenario_ml_errors.csv` | Expanded evaluation false-positive and false-negative rows. |

`scenario_evaluation_output.csv` was a stale duplicate prediction export with no
producer or consumer in the current code and has been removed.
