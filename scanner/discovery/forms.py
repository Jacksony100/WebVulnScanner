from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..models import RequestTemplate


SKIPPED_INPUT_TYPES = {"submit", "button", "reset", "image", "file"}


def extract_forms(page_url: str, soup: BeautifulSoup) -> list[RequestTemplate]:
    templates: list[RequestTemplate] = []
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").strip().upper()
        if method not in {"GET", "POST"}:
            method = "GET"
        action = form.get("action") or page_url
        target = urljoin(page_url, action)
        enctype = (form.get("enctype") or "application/x-www-form-urlencoded").strip().lower()
        values = _extract_controls(form)
        params = values if method == "GET" else {}
        data = values if method == "POST" else None
        templates.append(RequestTemplate(
            method=method,
            url=target,
            params=params,
            data=data,
            content_type=enctype,
            source="html-form",
            discovered_from=page_url,
            tags={"form"},
        ))
    return templates


def _extract_controls(form) -> dict[str, str]:
    values: dict[str, str] = {}
    for control in form.find_all(["input", "textarea", "select"]):
        name = control.get("name")
        if not name:
            continue
        tag = control.name.lower()
        if tag == "textarea":
            values[name] = control.text or control.get("value") or ""
            continue
        if tag == "select":
            selected = control.find("option", selected=True) or control.find("option")
            values[name] = selected.get("value") if selected and selected.has_attr("value") else (selected.text if selected else "")
            continue
        input_type = (control.get("type") or "text").lower()
        if input_type in SKIPPED_INPUT_TYPES:
            continue
        if input_type in {"checkbox", "radio"} and not control.has_attr("checked"):
            continue
        values[name] = control.get("value") or default_value_for_name(name)
    return values


def default_value_for_name(name: str) -> str:
    lowered = name.lower()
    if "email" in lowered:
        return "user@example.test"
    if "id" in lowered:
        return "1"
    if "url" in lowered or "next" in lowered or "redirect" in lowered:
        return "/"
    return "test"
