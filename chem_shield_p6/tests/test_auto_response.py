import pytest

from chem_shield_p6.auto_response import (
    COUNTDOWN, IDLE, LOCKED_OUT, RECOVERING, WATCHING, AutoResponder, AutoResponseConfig,
)

CRIT = {"incident_id": "INC-1", "status": "ACTIVE", "risk_level": "CRITICAL", "acknowledged": False}


class Rig:
    """Fake clock + fake machine so the 15 s flow runs instantly."""

    def __init__(self, **cfg):
        self.now = 0.0
        self.incident = dict(CRIT)
        self.abnormal = True
        self.running = True
        self.target = 1200
        self.log, self.calls = [], []
        self.fail_stop = False
        self.responder = AutoResponder(
            get_critical_incident=lambda: self.incident
            if self.incident and self.incident["risk_level"] == "CRITICAL"
            and self.incident["status"] == "ACTIVE" and not self.incident["acknowledged"] else None,
            get_incident=lambda _id: self.incident,
            read_state=lambda: {"target_rpm": self.target, "rpm": 1500 if self.abnormal else 900},
            limit_alerts=lambda s: [{"sensor": "speed"}] if self.abnormal else [],
            stop_machine=self._stop,
            clear_overrides=self._clear,
            start_machine=self._start,
            log_event=lambda *a: self.log.append(a[0]),
            config=AutoResponseConfig(**cfg),
            clock=lambda: self.now,
        )

    def _stop(self):
        if self.fail_stop:
            raise ConnectionError("PLC down")
        self.running = False
        self.calls.append("stop")

    def _clear(self):
        self.abnormal = False
        self.calls.append("clear")

    def _start(self, target):
        self.running = True
        self.calls.append(f"start:{target}")

    def advance(self, seconds, step=1.0):
        end = self.now + seconds
        while self.now < end:
            self.now += step
            self.responder.tick()


def test_countdown_starts_on_critical_and_does_not_stop_early():
    rig = Rig()
    rig.responder.tick()
    assert rig.responder.state == COUNTDOWN
    rig.advance(14)
    assert rig.running and rig.responder.state == COUNTDOWN
    assert 0 <= rig.responder.status()["seconds_remaining"] <= 1


def test_no_operator_response_stops_machine_after_15s_then_recovers_and_resumes():
    rig = Rig()
    rig.responder.tick()
    rig.advance(15)
    assert rig.calls[0] == "stop" and rig.responder.state == RECOVERING
    rig.advance(10)
    assert rig.calls[:3] == ["stop", "clear", "start:1200"]
    assert rig.running and rig.responder.state == WATCHING
    rig.advance(10)
    assert rig.responder.state == IDLE
    assert rig.log == [
        "P6_AUTO_COUNTDOWN_STARTED", "P6_AUTO_STOP", "P6_AUTO_RECOVERY",
    ]


def test_acknowledge_cancels_automatic_stop():
    rig = Rig()
    rig.responder.tick()
    rig.advance(5)
    rig.incident["acknowledged"] = True
    rig.advance(20)
    assert rig.running and "stop" not in rig.calls
    assert rig.responder.state == IDLE and "P6_AUTO_CANCELLED" in rig.log


def test_operator_command_during_countdown_cancels_it():
    rig = Rig()
    rig.responder.tick()
    rig.responder.operator_command("pause")
    rig.advance(30)
    assert rig.running and rig.responder.state == IDLE


def test_cancelled_incident_is_not_retriggered():
    rig = Rig()
    rig.responder.tick()
    assert rig.responder.operator_interacted("INC-1")
    rig.advance(30)
    assert rig.responder.state == IDLE and rig.log.count("P6_AUTO_COUNTDOWN_STARTED") == 1


def test_incident_clearing_cancels_countdown():
    rig = Rig()
    rig.responder.tick()
    rig.incident["status"] = "CLOSED"
    rig.advance(20)
    assert rig.running and "P6_AUTO_CANCELLED" in rig.log


def test_stays_stopped_if_readings_never_return_to_normal():
    rig = Rig(recovery_timeout_seconds=5)
    rig._clear = lambda: rig.calls.append("clear")  # attack persists: override cannot be cleared
    rig.responder._clear_overrides = rig._clear
    rig.responder.tick()
    rig.advance(40)
    assert rig.responder.state == LOCKED_OUT and not rig.running
    assert "P6_AUTO_RECOVERY_FAILED" in rig.log and not any(c.startswith("start") for c in rig.calls)


def test_anomaly_returning_after_restart_stops_again_and_locks_out():
    rig = Rig()
    rig.responder.tick()
    rig.advance(21)
    assert rig.responder.state == WATCHING
    rig.abnormal = True
    rig.advance(2)
    assert rig.responder.state == LOCKED_OUT and not rig.running


def test_operator_start_releases_lockout():
    rig = Rig(recovery_timeout_seconds=0)
    rig.responder._clear_overrides = lambda: None
    rig.responder.tick()
    rig.advance(30)
    assert rig.responder.state == LOCKED_OUT
    rig.responder.operator_command("start")
    assert rig.responder.state == IDLE


def test_failed_stop_is_reported_not_hidden():
    rig = Rig()
    rig.fail_stop = True
    rig.responder.tick()
    rig.advance(16)
    assert rig.responder.state == LOCKED_OUT and "P6_AUTO_STOP_FAILED" in rig.log
    assert "FAILED" in rig.responder.status()["message"]


def test_auto_resume_off_keeps_machine_stopped():
    rig = Rig(auto_resume=False)
    rig.responder.tick()
    rig.advance(30)
    assert rig.responder.state == LOCKED_OUT and not rig.running


def test_non_critical_never_triggers():
    rig = Rig()
    rig.incident["risk_level"] = "HIGH"
    rig.advance(30)
    assert rig.responder.state == IDLE and rig.running


def test_disabled_responder_does_nothing():
    rig = Rig()
    rig.responder.enabled = False
    rig.advance(30)
    assert rig.responder.state == IDLE and rig.running


def test_negative_timing_rejected():
    with pytest.raises(ValueError):
        AutoResponseConfig(countdown_seconds=-1)
