"""Safe logging helpers: only fingerprints/summaries, never raw sensitive values."""
from __future__ import annotations

import json
import logging

logger = logging.getLogger("privacy_gateway")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def log_decision(
    *,
    tenant_id: str,
    event_type: str,
    decision: str,
    reason: str,
    input_summary: dict,
    evidence: dict,
) -> None:
    # IMPORTANT: only pre-sanitized summaries/evidence are logged here.
    # Callers must never place raw sensitive values into these structures.
    payload = {
        "tenant_id": tenant_id,
        "event": event_type,
        "decision": decision,
        "reason": reason,
        "input_summary": input_summary,
        "evidence": evidence,
    }
    level = logging.INFO if decision == "allow" else logging.WARNING
    logger.log(
        level,
        "decision %s",
        json.dumps(payload, ensure_ascii=False, sort_keys=True),
    )
