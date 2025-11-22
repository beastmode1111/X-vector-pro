# core/brute.py

import time
from typing import Dict, Any, Optional

from core.logger import get_logger, log_event

logger = get_logger("BruteForceEngine")


class BruteForceEngine:
    """
    Safe simulation brute-force module for XVectorPro.
    DOES NOT perform real attacks.
    Only runs permitted internal auth simulations.
    """

    # IPs allowed for brute-force simulation (your lab env)
    SAFE_TARGETS = {"127.0.0.1", "localhost", "192.168.1.", "10.0.0."}

    def __init__(self):
        logger.info("BruteForceEngine initialized")

    # ------------------------------------------------------
    # Validation
    # ------------------------------------------------------
    def _is_approved_target(self, target: str) -> bool:
        """
        Ensures target is authorized for brute-force simulation.
        """
        for safe_prefix in self.SAFE_TARGETS:
            if target.startswith(safe_prefix):
                return True
        return False

    # ------------------------------------------------------
    # Simulated brute force attempt
    # ------------------------------------------------------
    def run(self, target: str) -> Dict[str, Any]:
        """
        Performs a SAFE, mock brute-force test on allowed targets.
        Returns structured results for analyzer.

        This simulates:
        - credential attempts
        - timing
        - detection of weak/no auth
        """

        logger.info(f"Brute force module invoked on target: {target}")

        # Validate target
        if not self._is_approved_target(target):
            logger.warning(f"Brute force blocked: {target} is not approved.")
            log_event(
                category="bruteforce_blocked",
                data={"target": target, "reason": "not_approved"},
                level="warning"
            )
            return {
                "status": "blocked",
                "target": target,
                "reason": "Unauthorized target"
            }

        log_event(
            category="bruteforce_start",
            data={"target": target},
            level="info"
        )

        start_time = time.time()

        # ---- MOCK AUTH DATASET ----
        test_credentials = [
            {"username": "admin", "password": "admin123"},
            {"username": "root", "password": "toor"},
            {"username": "user", "password": "password"},
        ]

        results = []
        for attempt in test_credentials:
            time.sleep(0.25)  # simulate delay
            attempt_result = {
                "username": attempt["username"],
                "password": attempt["password"],
                "success": False  # always false (simulation only)
            }
            results.append(attempt_result)

            log_event(
                category="bruteforce_attempt",
                data=attempt_result,
                level="info"
            )

        end_time = time.time()

        summary = {
            "target": target,
            "status": "completed",
            "attempts": len(results),
            "successful": False,
            "duration_sec": round(end_time - start_time, 3),
            "results": results
        }

        log_event(
            category="bruteforce_summary",
            data=summary,
            write_structured_file=True,
            level="info"
        )

        logger.info("Brute-force simulation completed")

        return summary


# ------------------------------------------------------
# Shortcut function (for sequencer compatibility)
# ------------------------------------------------------

_engine = BruteForceEngine()

def brute_force_login(target: str) -> Dict[str, Any]:
    """
    The public entry point used by run_sequence().
    """
    return _engine.run(target)
