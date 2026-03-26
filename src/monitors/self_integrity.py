"""
CENTINELA – Self-Integrity Monitor.

Computes SHA-256 hashes of all .py files under src/ at startup, then
re-checks every 30 minutes.  Any addition, removal, or modification raises
a CENTINELA_INTEGRITY alert so operators know the monitoring agent itself
may have been tampered with.
"""

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Dict

from config.models import GlobalConfig
from alerts.manager import AlertManager

logger = logging.getLogger("centinela.monitors.self_integrity")

# How often (seconds) to re-check the integrity of the source files.
_CHECK_INTERVAL = 1800  # 30 minutes

# src/ directory: this file lives at src/monitors/self_integrity.py,
# so src/ is the parent of this file's parent directory.
_SRC_DIR = Path(__file__).resolve().parent.parent


class SelfIntegrityMonitor:
    """
    Monitors the integrity of CENTINELA's own source files.

    At startup, computes SHA-256 hashes for all .py files under src/ and
    stores them as a baseline.  Every _CHECK_INTERVAL seconds it recomputes
    the hashes and compares against the baseline, raising a critical alert
    if any file was modified, added, or removed.

    This monitor NEVER modifies or deletes any files.

    Parameters
    ----------
    config:        Global CENTINELA configuration.
    alert_manager: Shared AlertManager for deduplication + dispatch.
    """

    def __init__(self, config: GlobalConfig, alert_manager: AlertManager) -> None:
        self._config = config
        self._alert_manager = alert_manager

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Compute hashes at startup, then check every 30 min."""
        logger.info(
            "SelfIntegrityMonitor starting – scanning %s for baseline.", _SRC_DIR
        )
        baseline = self._compute_hashes()
        logger.info(
            "SelfIntegrityMonitor baseline captured: %d .py file(s).", len(baseline)
        )

        try:
            while True:
                await asyncio.sleep(_CHECK_INTERVAL)
                await self._check_integrity(baseline)
        except asyncio.CancelledError:
            logger.info("SelfIntegrityMonitor cancelled.")
            raise

    # ------------------------------------------------------------------
    # Hash computation
    # ------------------------------------------------------------------

    def _compute_hashes(self) -> Dict[str, str]:
        """
        SHA-256 of all .py files under src/.

        Returns a dict mapping relative path strings (relative to _SRC_DIR)
        to their hex digest.  Skips __pycache__ directories, .pyc files, and
        the centinela_test.db file.
        """
        hashes: Dict[str, str] = {}
        for path in _SRC_DIR.rglob("*.py"):
            # Skip __pycache__ directories and compiled .pyc files
            if "__pycache__" in path.parts:
                continue
            if path.suffix == ".pyc":
                continue
            # Skip the test database if it somehow ends up with a .py extension
            if path.name == "centinela_test.db":
                continue

            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                rel = str(path.relative_to(_SRC_DIR))
                hashes[rel] = digest
            except OSError as exc:
                logger.warning(
                    "SelfIntegrityMonitor: could not hash %s: %s", path, exc
                )

        return hashes

    # ------------------------------------------------------------------
    # Integrity check
    # ------------------------------------------------------------------

    async def _check_integrity(self, baseline: Dict[str, str]) -> None:
        """
        Compare current hashes to baseline.  Alert on any difference.

        Detects:
        - Modified files  (same path, different hash)
        - Added files     (path not in baseline)
        - Removed files   (path in baseline but no longer on disk)
        """
        current = self._compute_hashes()

        all_paths = set(baseline) | set(current)
        changed_files = []

        for rel_path in sorted(all_paths):
            baseline_hash = baseline.get(rel_path)
            current_hash = current.get(rel_path)

            if baseline_hash is None:
                changed_files.append({"path": rel_path, "change": "added"})
            elif current_hash is None:
                changed_files.append({"path": rel_path, "change": "removed"})
            elif baseline_hash != current_hash:
                changed_files.append(
                    {
                        "path": rel_path,
                        "change": "modified",
                        "baseline_hash": baseline_hash,
                        "current_hash": current_hash,
                    }
                )

        if not changed_files:
            logger.debug(
                "SelfIntegrityMonitor: all %d file(s) unchanged.", len(baseline)
            )
            return

        logger.alert(
            "CENTINELA INTEGRITY VIOLATION: %d file(s) changed – %s",
            len(changed_files),
            ", ".join(
                f"{c['change']}:{c['path']}" for c in changed_files
            ),
        )

        evidence = {
            "changed_files": changed_files,
            "baseline_count": len(baseline),
            "current_count": len(current),
            "src_dir": str(_SRC_DIR),
        }

        await self._alert_manager.raise_alert(
            project=None,
            container_name="centinela",
            container_id="",
            alert_type="CENTINELA_INTEGRITY",
            severity="critical",
            rule="self_file_modified",
            evidence=evidence,
            dedup_extra=",".join(sorted(c["path"] for c in changed_files)),
        )
