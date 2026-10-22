from __future__ import annotations

import sqlite3

import pytest

from admin_part.storage import add_audit, initialize
from chem_shield_p7.audit_chain.chain import verify_chain


def seed(database):
    initialize(database)
    for action in ("login_success", "incident_acknowledge", "logout"):
        add_audit(
            database,
            username="admin",
            role="administrator",
            source_ip="127.0.0.1",
            action=action,
            detail=action,
        )


def test_audit_chain_verifies_existing_and_new_records(tmp_path):
    database = tmp_path / "admin.db"
    seed(database)
    result = verify_chain(str(database))
    assert result == {"ok": True, "records": 3}


@pytest.mark.parametrize("tamper", ["edit", "delete", "reorder"])
def test_audit_chain_detects_edit_delete_and_reorder(tmp_path, tamper):
    database = tmp_path / f"{tamper}.db"
    seed(database)
    with sqlite3.connect(database) as connection:
        if tamper == "edit":
            connection.execute("UPDATE audit_log SET detail='changed' WHERE id=2")
        elif tamper == "delete":
            connection.execute("DELETE FROM audit_log WHERE id=2")
        else:
            connection.execute(
                "UPDATE p7_audit_chain SET chain_order=-1 WHERE chain_order=1"
            )
            connection.execute(
                "UPDATE p7_audit_chain SET chain_order=1 WHERE chain_order=2"
            )
            connection.execute(
                "UPDATE p7_audit_chain SET chain_order=2 WHERE chain_order=-1"
            )
    if tamper == "delete":
        initialize(database)
    result = verify_chain(str(database))
    assert result["ok"] is False
    if tamper == "reorder":
        assert result["first_broken_index"] == 1
    else:
        assert result["first_broken_index"] >= 2


def test_legacy_audit_rows_are_chained_once(tmp_path):
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, timestamp TEXT, username TEXT, "
            "role TEXT, source_ip TEXT, action TEXT, incident_id TEXT, detail TEXT)"
        )
        connection.execute(
            "INSERT INTO audit_log VALUES (1, 't', 'admin', 'administrator', '127.0.0.1', 'old', NULL, 'old row')"
        )
    initialize(database)
    assert verify_chain(str(database)) == {"ok": True, "records": 1}
