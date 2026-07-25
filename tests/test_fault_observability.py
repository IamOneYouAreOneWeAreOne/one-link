from __future__ import annotations

import logging

import pytest

from one_link import fault_observability


@pytest.fixture(autouse=True)
def _clear_limiter() -> None:
    fault_observability._reset_for_tests()


def test_reports_only_sanitized_operation_and_exception_class(caplog) -> None:
    logger = logging.getLogger("one_link.test_fault_observability")
    secret = "C:/private/token.txt?bearer=do-not-log"

    with caplog.at_level(logging.WARNING, logger=logger.name):
        emitted = fault_observability.report_best_effort_failure(
            logger,
            "cleanup\npeer supplied",
            RuntimeError(secret),
            now=10.0,
        )

    assert emitted is True
    rendered = caplog.records[-1].getMessage()
    assert "cleanup_peer_supplied" in rendered
    assert "RuntimeError" in rendered
    assert secret not in rendered
    assert "do-not-log" not in rendered


def test_duplicate_failure_is_rate_limited_by_operation_and_class(caplog) -> None:
    logger = logging.getLogger("one_link.test_fault_observability.rate")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        assert fault_observability.report_best_effort_failure(
            logger, "close", OSError("first secret"), now=20.0, interval_s=60
        )
        assert not fault_observability.report_best_effort_failure(
            logger, "close", OSError("second secret"), now=21.0, interval_s=60
        )
        assert fault_observability.report_best_effort_failure(
            logger, "close", ValueError("different class"), now=21.0, interval_s=60
        )

    assert len(caplog.records) == 2


def test_nonfinite_tuning_values_do_not_disable_bounding(caplog) -> None:
    logger = logging.getLogger("one_link.test_fault_observability.nonfinite")

    with caplog.at_level(logging.WARNING, logger=logger.name):
        assert fault_observability.report_best_effort_failure(
            logger, "flush", OSError(), now=float("nan"), interval_s=float("nan")
        )

    assert len(caplog.records) == 1


def test_broken_logging_handler_does_not_escape() -> None:
    class BrokenLogger:
        name = "one_link.broken"

        def log(self, *_args, **_kwargs) -> None:
            raise RuntimeError("handler failed")

    assert not fault_observability.report_best_effort_failure(
        BrokenLogger(),  # type: ignore[arg-type]
        "cleanup",
        OSError("sensitive"),
        now=30.0,
    )
