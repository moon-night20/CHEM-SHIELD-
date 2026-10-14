"""Compatibility entry point for the historical misspelled script name.

Use scripts/generate_test_scenarios.py for new work.
"""

from scripts.generate_test_scenarios import generate_test_scenarios, main

__all__ = ["generate_test_scenarios"]

if __name__ == "__main__":
    main()
