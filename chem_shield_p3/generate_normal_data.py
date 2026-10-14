"""Compatibility entry point; use scripts/generate_normal_data.py for new work."""

from scripts.generate_normal_data import generate_normal_data, main

__all__ = ["generate_normal_data"]

if __name__ == "__main__":
    main()
