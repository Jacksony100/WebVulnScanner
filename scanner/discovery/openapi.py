from __future__ import annotations

import json
from urllib.parse import urljoin

from ..models import RequestTemplate


SAFE_OPENAPI_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}


def parse_openapi_document(base_url: str, body: str, discovered_from: str) -> list[RequestTemplate]:
    try:
        spec = json.loads(body or "{}")
    except json.JSONDecodeError:
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    templates: list[RequestTemplate] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            method_upper = method.upper()
            if method_upper not in SAFE_OPENAPI_METHODS:
                continue
            if not isinstance(operation, dict):
                operation = {}
            url = urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
            params = {}
            for parameter in operation.get("parameters") or []:
                if not isinstance(parameter, dict):
                    continue
                location = parameter.get("in")
                name = parameter.get("name")
                if location == "query" and name:
                    params[str(name)] = _example_value(parameter)
            content_type, json_body, data = _request_body(operation)
            tags = {"api", "openapi"}
            if method_upper in {"PUT", "PATCH", "DELETE"}:
                tags.add("unsafe-method")
            templates.append(RequestTemplate(
                method=method_upper,
                url=url,
                params=params,
                data=data,
                json_body=json_body,
                content_type=content_type,
                source="openapi",
                discovered_from=discovered_from,
                tags=tags,
            ))
    return templates


def _example_value(parameter: dict) -> str:
    if "example" in parameter:
        return str(parameter["example"])
    schema = parameter.get("schema") or {}
    if schema.get("type") in {"integer", "number"}:
        return "1"
    if schema.get("format") == "email":
        return "user@example.test"
    return "test"


def _request_body(operation: dict):
    body = operation.get("requestBody") or {}
    content = body.get("content") or {}
    if "application/json" in content:
        schema = content["application/json"].get("schema") or {}
        return "application/json", _json_from_schema(schema), None
    if "application/x-www-form-urlencoded" in content:
        schema = content["application/x-www-form-urlencoded"].get("schema") or {}
        return "application/x-www-form-urlencoded", None, _object_from_schema(schema)
    return None, None, None


def _json_from_schema(schema: dict):
    if schema.get("type") == "object" or "properties" in schema:
        return _object_from_schema(schema)
    if schema.get("type") == "array":
        return []
    return "test"


def _object_from_schema(schema: dict) -> dict[str, str]:
    properties = schema.get("properties") or {}
    if not properties:
        return {}
    return {str(name): _schema_value(prop) for name, prop in properties.items()}


def _schema_value(schema: dict):
    if "example" in schema:
        return schema["example"]
    if schema.get("type") in {"integer", "number"}:
        return 1
    if schema.get("type") == "boolean":
        return True
    if schema.get("format") == "email":
        return "user@example.test"
    return "test"
