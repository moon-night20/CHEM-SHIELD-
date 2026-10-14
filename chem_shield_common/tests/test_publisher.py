import unittest
from unittest.mock import patch
from urllib.error import URLError

from chem_shield_common.publisher import publish_events


class FakeResponse:
    status = 200

    def __init__(self, accepted):
        self.body = f'{{"accepted": {accepted}, "rejected": 0}}'.encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class PublisherTests(unittest.TestCase):
    @patch("chem_shield_common.publisher._open_local", side_effect=URLError("offline"))
    def test_hmi_failure_is_reported_without_raising(self, open_local):
        result = publish_events(
            [{"event_type": "network"}],
            retries=1,
            backoff=0,
        )

        self.assertEqual(open_local.call_count, 2)
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["failed_batches"], 1)
        self.assertIn("HMI request failed", result["errors"][0])

    @patch(
        "chem_shield_common.publisher._open_local",
        side_effect=[FakeResponse(2), FakeResponse(1)],
    )
    def test_batches_events_and_reports_hmi_counts(self, open_local):
        with self.assertLogs("chem_shield_common.publisher", level="INFO") as logs:
            result = publish_events(
                [{"event_id": "one"}, {"event_id": "two"}, {"event_id": "three"}],
                batch_size=2,
            )

        self.assertEqual(open_local.call_count, 2)
        self.assertEqual(result["batches"], 2)
        self.assertEqual(result["accepted"], 3)
        self.assertEqual(result["rejected"], 0)
        self.assertTrue(any("accepted 2 and rejected 0" in line for line in logs.output))

    def test_non_loopback_url_is_rejected_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            publish_events([], url="http://example.com/api/risk/events")
