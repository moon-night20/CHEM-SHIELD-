"""Compatibility entry point; use scripts/evaluate_model.py for new work."""

from scripts.evaluate_model import calculate_evaluation, main

__all__ = ["calculate_evaluation"]

if __name__ == "__main__":
    main()
