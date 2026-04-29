from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass
class ResponseFingerprint:
    status: int
    normalized_length: int
    word_count: int
    title: str | None
    hash: str


def normalize_dynamic_body(text: str) -> str:
    value = text or ""
    value = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", value, flags=re.I)
    value = re.sub(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?\b", "<datetime>", value)
    value = re.sub(r"\b\d{10,13}\b", "<timestamp>", value)
    value = re.sub(r"(csrf|nonce|token|session)[A-Za-z0-9_.:-]*(['\"\s:=]+)[A-Za-z0-9._-]+", r"\1\2<token>", value, flags=re.I)
    value = re.sub(r"[0-9a-f]{12,}", "<hex>", value, flags=re.I)
    return value


def fingerprint_response(snapshot) -> ResponseFingerprint:
    normalized = normalize_dynamic_body(snapshot.text_sample)
    return ResponseFingerprint(
        status=snapshot.status_code,
        normalized_length=len(normalized),
        word_count=len(normalized.split()),
        title=snapshot.title,
        hash=hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest(),
    )


def compare_fingerprints(left: ResponseFingerprint, right: ResponseFingerprint) -> float:
    score = 0.0
    if left.status == right.status:
        score += 0.35
    max_len = max(left.normalized_length, right.normalized_length, 1)
    score += max(0.0, 0.35 * (1 - abs(left.normalized_length - right.normalized_length) / max_len))
    max_words = max(left.word_count, right.word_count, 1)
    score += max(0.0, 0.20 * (1 - abs(left.word_count - right.word_count) / max_words))
    if left.title == right.title:
        score += 0.10
    return min(1.0, score)


class BaselineCollector:
    async def collect(self, template, client):
        try:
            first = await client.send(template, check_name="baseline")
            second = await client.send(template, check_name="baseline")
        except Exception:
            return None
        return {
            "snapshots": [first, second],
            "fingerprints": [fingerprint_response(first), fingerprint_response(second)],
            "stable": compare_fingerprints(fingerprint_response(first), fingerprint_response(second)) > 0.85,
        }
