"""Create, list, or delete local administrator-console users."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Callable

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "data" / "users.json"
ROLES = ("administrator", "analyst", "operator")
MIN_PASSWORD_LENGTH = 10
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _load_users(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as stream:
        users = json.load(stream)
    if not isinstance(users, dict) or any(not isinstance(value, dict) for value in users.values()):
        raise ValueError("users.json must contain a JSON object of user records")
    return users


def _save_users(path: Path, users: dict[str, dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=".users.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(users, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def main(
    argv: list[str] | None = None,
    *,
    users_path: str | Path = USERS_FILE,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    parser = argparse.ArgumentParser(description="Manage local CHEM-SHIELD admin-console users")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create", help="create a user with a prompted password")
    create_parser.add_argument("username")
    create_parser.add_argument("--role", required=True, choices=ROLES)
    list_parser = subparsers.add_parser("list", help="list usernames and roles")
    list_parser.set_defaults(command="list")
    delete_parser = subparsers.add_parser("delete", help="delete a user")
    delete_parser.add_argument("username")
    args = parser.parse_args(argv)
    path = Path(users_path)

    try:
        users = _load_users(path)
        if args.command == "create":
            if not USERNAME_PATTERN.fullmatch(args.username):
                raise ValueError("username must be 1-64 letters, digits, dots, underscores, or hyphens")
            if args.username in users:
                raise ValueError(f"user {args.username!r} already exists")
            password = prompt("Password (minimum 10 characters): ")
            confirmation = prompt("Confirm password: ")
            if len(password) < MIN_PASSWORD_LENGTH:
                raise ValueError("password must be at least 10 characters")
            if password != confirmation:
                raise ValueError("passwords do not match")
            users[args.username] = {
                "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
                "role": args.role,
            }
            _save_users(path, users)
            print(f"Created {args.role} user {args.username}.")
        elif args.command == "list":
            for username, record in sorted(users.items()):
                print(f"{username}\t{record.get('role', 'invalid')}")
            if not users:
                print("No users configured.")
        else:
            if args.username not in users:
                raise ValueError(f"user {args.username!r} does not exist")
            del users[args.username]
            _save_users(path, users)
            print(f"Deleted user {args.username}.")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"User management failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
