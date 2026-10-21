"""Simulation-only automatic response for active CRITICAL incidents.

Flow:
    IDLE -> COUNTDOWN (operator warned, default 15 s)
         -> operator acts            : countdown cancelled, operator stays in charge
         -> no operator action       : machine is stopped automatically
    STOPPED -> RECOVERING            : abnormal state is cleared, readings re-checked
         -> readings normal          : machine restarts at its previous target (WATCHING)
         -> readings still abnormal  : machine stays stopped (LOCKED_OUT, operator needed)
    WATCHING                         : short grace period; a new critical reading
                                       stops the machine again and locks it out

The class has no I/O of its own. Every side effect is an injected callable, so it
can be tested with a fake clock and fake machine, and it only ever acts on the
loopback virtual PLC supplied by the HMI.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

IDLE = "IDLE"
COUNTDOWN = "COUNTDOWN"
RECOVERING = "RECOVERING"
WATCHING = "WATCHING"
LOCKED_OUT = "LOCKED_OUT"


@dataclass(frozen=True)
class AutoResponseConfig:
    countdown_seconds: float = 15.0
    recovery_hold_seconds: float = 5.0  # machine stays stopped this long before checking
    recovery_timeout_seconds: float = 15.0  # give up waiting for normal readings
    watch_seconds: float = 10.0  # grace period after restart
    auto_resume: bool = True

    def __post_init__(self) -> None:
        for name in (
            "countdown_seconds",
            "recovery_hold_seconds",
            "recovery_timeout_seconds",
            "watch_seconds",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must not be negative")


class AutoResponder:
    def __init__(
        self,
        *,
        get_critical_incident: Callable[[], Optional[Mapping[str, Any]]],
        get_incident: Callable[[str], Optional[Mapping[str, Any]]],
        read_state: Callable[[], Mapping[str, Any]],
        limit_alerts: Callable[[Mapping[str, Any]], list],
        stop_machine: Callable[[], None],
        clear_overrides: Callable[[], None],
        start_machine: Callable[[int], None],
        log_event: Callable[[str, str, str, str], None],
        config: Optional[AutoResponseConfig] = None,
        clock: Callable[[], float] = time.monotonic,
        enabled: bool = True,
    ) -> None:
        self._get_critical = get_critical_incident
        self._get_incident = get_incident
        self._read_state = read_state
        self._limit_alerts = limit_alerts
        self._stop = stop_machine
        self._clear_overrides = clear_overrides
        self._start = start_machine
        self._log = log_event
        self.config = config or AutoResponseConfig()
        self._clock = clock
        self.enabled = enabled
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self.state = IDLE
        self.incident_id: Optional[str] = None
        self.message = "Monitoring. No critical incident."
        self._deadline = 0.0
        self._phase_started = 0.0
        self._previous_target = 0
        self._overrides_cleared = False
        self._handled: set[str] = set()

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        with self._lock:
            remaining = None
            if self.state == COUNTDOWN:
                remaining = max(0.0, self._deadline - self._clock())
            return {
                "enabled": self.enabled,
                "state": self.state,
                "incident_id": self.incident_id,
                "seconds_remaining": None if remaining is None else round(remaining, 1),
                "countdown_seconds": self.config.countdown_seconds,
                "message": self.message,
                "simulation_only": True,
            }

    # ------------------------------------------------------ operator interaction
    def operator_interacted(self, incident_id: Optional[str] = None) -> bool:
        """Cancel a pending automatic stop. Returns True if a countdown was cancelled."""
        with self._lock:
            if self.state != COUNTDOWN:
                return False
            if incident_id is not None and incident_id != self.incident_id:
                return False
            cancelled = self.incident_id
            self._handled.add(cancelled)
            self._log(
                "P6_AUTO_CANCELLED", f"auto_stop ({cancelled})", "COUNTDOWN", "OPERATOR_IN_CONTROL"
            )
            self._reset_to_idle("Operator took over. Automatic stop cancelled.")
            return True

    def operator_command(self, action: str) -> None:
        """Any operator machine command counts as interaction; a start releases a lockout."""
        with self._lock:
            if self.state == COUNTDOWN:
                self.operator_interacted()
            elif self.state in (LOCKED_OUT, RECOVERING, WATCHING) and action == "start":
                self._reset_to_idle("Operator restarted the machine manually.")

    # -------------------------------------------------------------------- engine
    def tick(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            now = self._clock()
            if self.state == IDLE:
                self._tick_idle(now)
            elif self.state == COUNTDOWN:
                self._tick_countdown(now)
            elif self.state == RECOVERING:
                self._tick_recovering(now)
            elif self.state == WATCHING:
                self._tick_watching(now)

    def _tick_idle(self, now: float) -> None:
        incident = self._get_critical()
        if not incident:
            return
        incident_id = incident.get("incident_id")
        if not isinstance(incident_id, str) or incident_id in self._handled:
            return
        self.state = COUNTDOWN
        self.incident_id = incident_id
        self._deadline = now + self.config.countdown_seconds
        self.message = (
            f"CRITICAL incident {incident_id}. Machine will stop automatically in "
            f"{self.config.countdown_seconds:g} s unless the operator responds."
        )
        self._log(
            "P6_AUTO_COUNTDOWN_STARTED",
            f"auto_stop ({incident_id})",
            "RUNNING",
            f"STOP_IN_{self.config.countdown_seconds:g}S",
        )

    def _tick_countdown(self, now: float) -> None:
        incident = self._get_incident(self.incident_id)
        still_critical = (
            incident is not None
            and incident.get("status") == "ACTIVE"
            and incident.get("risk_level") == "CRITICAL"
        )
        if incident is not None and incident.get("acknowledged"):
            self.operator_interacted(self.incident_id)
            return
        if not still_critical:
            self._log(
                "P6_AUTO_CANCELLED",
                f"auto_stop ({self.incident_id})",
                "COUNTDOWN",
                "INCIDENT_CLEARED",
            )
            self._reset_to_idle("Incident is no longer critical. Automatic stop cancelled.")
            return
        if now < self._deadline:
            return
        self._execute_stop(now)

    def _execute_stop(self, now: float) -> None:
        try:
            state = self._read_state()
            self._previous_target = int(state.get("target_rpm") or 0)
            self._stop()
        except Exception as error:  # PLC unreachable: do not pretend the stop happened
            self.message = f"Automatic stop FAILED: {error}. Operator action required."
            self._log("P6_AUTO_STOP_FAILED", f"motor_status ({self.incident_id})", "RUNNING", "STOP_FAILED")
            self._handled.add(self.incident_id)
            self.state = LOCKED_OUT
            return
        self._handled.add(self.incident_id)
        self._log(
            "P6_AUTO_STOP", f"motor_status ({self.incident_id})", "RUNNING", "STOPPED"
        )
        self.state = RECOVERING
        self._phase_started = now
        self._overrides_cleared = False
        self.message = (
            "No operator response. Machine stopped automatically. "
            "Clearing the abnormal state and re-checking readings."
        )

    def _tick_recovering(self, now: float) -> None:
        elapsed = now - self._phase_started
        if elapsed < self.config.recovery_hold_seconds:
            return
        try:
            if not self._overrides_cleared:
                self._clear_overrides()
                self._overrides_cleared = True
                return  # let the process publish fresh readings before checking
            state = self._read_state()
            alerts = self._limit_alerts(state)
        except Exception as error:
            self._lock_out(f"Recovery check failed: {error}")
            return
        if not alerts:
            if not self.config.auto_resume or self._previous_target <= 0:
                self._lock_out("Readings are normal. Auto-resume is off; operator must restart.")
                return
            try:
                self._start(self._previous_target)
            except Exception as error:
                self._lock_out(f"Restart failed: {error}")
                return
            self._log(
                "P6_AUTO_RECOVERY",
                f"motor_status ({self.incident_id})",
                "STOPPED",
                "RUNNING",
            )
            self.state = WATCHING
            self._phase_started = now
            self.message = "Readings back to normal. Machine restarted and under watch."
            return
        if elapsed >= self.config.recovery_hold_seconds + self.config.recovery_timeout_seconds:
            sensors = ", ".join(a["sensor"] for a in alerts)
            self._lock_out(f"Readings still abnormal ({sensors}). Machine kept stopped.")

    def _tick_watching(self, now: float) -> None:
        try:
            alerts = self._limit_alerts(self._read_state())
        except Exception:
            alerts = []
        if alerts:
            try:
                self._stop()
            except Exception:
                pass
            self._lock_out("Abnormal readings returned after restart. Machine stopped again.")
            return
        if now - self._phase_started >= self.config.watch_seconds:
            self._reset_to_idle("Recovered. Machine running normally.")

    # ------------------------------------------------------------------ helpers
    def _lock_out(self, reason: str) -> None:
        self._log(
            "P6_AUTO_RECOVERY_FAILED",
            f"motor_status ({self.incident_id})",
            "STOPPED",
            "OPERATOR_REQUIRED",
        )
        self.state = LOCKED_OUT
        self.message = f"{reason} Operator must inspect and restart manually."

    def _reset_to_idle(self, message: str) -> None:
        self.state = IDLE
        self.incident_id = None
        self.message = message
        self._overrides_cleared = False

    # ------------------------------------------------------------------ threading
    def start(self, interval: float = 1.0) -> None:
        if self._thread and self._thread.is_alive():
            return

        def loop() -> None:
            while not self._stop_event.wait(interval):
                try:
                    self.tick()
                except Exception:  # never let the watchdog thread die
                    pass

        self._thread = threading.Thread(target=loop, name="p6-auto-response", daemon=True)
        self._thread.start()

    def shutdown(self) -> None:
        self._stop_event.set()
