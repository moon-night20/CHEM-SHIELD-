"""Compatibility entry point for batch physical anomaly detection.

Use ``scripts/run_detection.py`` for new workflows or import
``src.detector.PhysicalAnomalyDetector`` from Python.
"""

from src.detector import PhysicalAnomalyDetector


if __name__ == "__main__":
    from scripts.run_detection import main

    main()
