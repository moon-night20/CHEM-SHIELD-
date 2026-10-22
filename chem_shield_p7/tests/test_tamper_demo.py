from __future__ import annotations

import pytest

from admin_part.storage import add_audit, initialize
from scripts.p7_tamper_demo import create_tampered_copy
from chem_shield_p7.audit_chain.chain import verify_chain


def test_tamper_demo_only_changes_a_copy(tmp_path):
    live = tmp_path / "admin.db"
    copy = tmp_path / "demo-copy.db"
    initialize(live)
    add_audit(
        live,
        username="admin",
        role="administrator",
        source_ip="127.0.0.1",
        action="demo",
        detail="original",
    )
    create_tampered_copy(live, copy, live_database=live)
    assert verify_chain(str(live))["ok"] is True
    assert verify_chain(str(copy))["ok"] is False


def test_tamper_demo_refuses_live_database_destination(tmp_path):
    live = tmp_path / "admin.db"
    initialize(live)
    with pytest.raises(ValueError, match="live Admin database"):
        create_tampered_copy(live, live, live_database=live)
