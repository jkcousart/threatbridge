from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime
from .http_client import request_json

DEFAULT_QUERY = """
query ThreatBridgeReports($first: Int!, $after: ID) {
  reports(first: $first, after: $after, orderBy: modified, orderMode: desc) {
    pageInfo { hasNextPage endCursor }
    edges {
      node {
        id
        name
        description
        published
        modified
        confidence
        objectMarking { definition }
        objects(all: true) {
          edges {
            node {
              ... on BasicObject { id entity_type }
              ... on AttackPattern {
                name
                x_mitre_id
                externalReferences {
                  edges { node { source_name external_id } }
                }
              }
              ... on Vulnerability { name }
            }
          }
        }
      }
    }
  }
}
"""


def _connection_nodes(value: Any) -> list[Mapping[str, Any]]:
    """Accept OpenCTI Relay connections as well as direct object lists."""

    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if not isinstance(value, Mapping):
        return []

    edges = value.get("edges")
    if isinstance(edges, list):
        nodes = []
        for edge in edges:
            if not isinstance(edge, Mapping):
                continue
            node = edge.get("node")
            if isinstance(node, Mapping):
                nodes.append(node)
        return nodes

    nodes = value.get("nodes")
    if isinstance(nodes, list):
        return [item for item in nodes if isinstance(item, Mapping)]
    return []


def _url_origin(value: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("OpenCTI URL is malformed") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("OpenCTI URL must be an HTTP or HTTPS origin without userinfo")
    hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    if effective_port < 1:
        raise ValueError("OpenCTI URL port must be between 1 and 65535")
    return parsed.scheme, hostname, effective_port


def _bounded_integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"OpenCTI {name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"OpenCTI {name} must be between {minimum} and {maximum}")
    return parsed


def _reports_connection(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise ValueError("OpenCTI GraphQL response was malformed")
    reports = data.get("reports")
    if not isinstance(reports, Mapping):
        raise ValueError("OpenCTI GraphQL response was malformed")
    edges = reports.get("edges")
    page_info = reports.get("pageInfo")
    if not isinstance(edges, list) or not isinstance(page_info, Mapping):
        raise ValueError("OpenCTI GraphQL response was malformed")
    if any(
        not isinstance(edge, Mapping) or not isinstance(edge.get("node"), Mapping)
        for edge in edges
    ):
        raise ValueError("OpenCTI GraphQL response was malformed")
    return reports


def _read_only_query(value: Any) -> str:
    query = str(value or DEFAULT_QUERY)
    operation = re.sub(r"(?m)^\s*#.*$", "", query).lstrip()
    if re.match(r"(?:query\b|\{)", operation, flags=re.IGNORECASE) is None:
        raise ValueError("OpenCTI configuration.query must be a read-only GraphQL query")
    return query


class OpenCtiReportsAdapter(IntegrationAdapter):
    adapter_key = "opencti-reports"
    supported_object_types = ("threat_report",)
    configuration_schema = {
        "required": ["base_url"],
        "properties": {
            "base_url": {"type": "string"},
            "graphql_url": {"type": "string"},
            "page_size": {"type": "integer", "minimum": 1, "maximum": 500},
            "query": {"type": "string"},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 120},
        },
    }
    display_name = "OpenCTI reports"
    description = "Imports reports through the authenticated OpenCTI GraphQL API."
    configuration_example = {
        "base_url": "https://opencti.example.org",
        "page_size": 100,
    }

    def _endpoint(self, context: SyncContext) -> str:
        base_url = str(context.configuration.get("base_url", "")).rstrip("/")
        if not base_url:
            raise ValueError("OpenCTI adapter requires configuration.base_url")
        parsed_base = urlsplit(base_url)
        if parsed_base.query or parsed_base.fragment:
            raise ValueError("OpenCTI base_url must not contain a query or fragment")
        endpoint = str(context.configuration.get("graphql_url") or f"{base_url}/graphql")
        if _url_origin(base_url) != _url_origin(endpoint):
            raise ValueError("OpenCTI graphql_url must use the configured base_url origin")
        return endpoint

    def _token(self, context: SyncContext) -> str:
        token = str(context.secrets.get("token") or context.secrets.get("value") or "").strip()
        if not token:
            raise ValueError("OpenCTI secret must contain token")
        return token

    def _request(self, context: SyncContext, variables: Mapping[str, Any]) -> Mapping[str, Any]:
        timeout = _bounded_integer(
            context.configuration.get("timeout_seconds", 60),
            name="timeout_seconds",
            minimum=1,
            maximum=120,
        )
        payload = request_json(
            self._endpoint(context),
            method="POST",
            headers={"Authorization": f"Bearer {self._token(context)}"},
            json_body={
                "query": _read_only_query(context.configuration.get("query")),
                "variables": dict(variables),
            },
            timeout=timeout,
        )
        errors = payload.get("errors")
        if errors:
            raise ValueError("OpenCTI GraphQL request failed")
        return payload

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        payload = self._request(context, {"first": 1, "after": None})
        reports = _reports_connection(payload)
        return {
            "ok": True,
            "records_returned": len(reports.get("edges", [])),
            "has_next_page": bool(reports.get("pageInfo", {}).get("hasNextPage")),
        }

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        payload = self._request(
            context,
            {
                "first": _bounded_integer(
                    context.configuration.get("page_size", 100),
                    name="page_size",
                    minimum=1,
                    maximum=500,
                ),
                "after": cursor.get("after") or None,
            },
        )
        reports = _reports_connection(payload)
        edges = reports.get("edges", [])
        records = [edge.get("node", {}) for edge in edges if edge.get("node")]
        page_info = reports.get("pageInfo", {})
        has_more = bool(page_info.get("hasNextPage"))
        end_cursor = page_info.get("endCursor")
        return PullBatch(
            records=records,
            next_cursor={"after": end_cursor} if has_more and end_cursor else {},
            has_more=has_more,
            snapshot_complete=not has_more,
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        report_id = str(raw_record.get("id", "")).strip()
        title = str(raw_record.get("name", "")).strip()
        if not report_id or not title:
            raise ValueError("OpenCTI report requires id and name")
        techniques: list[dict[str, Any]] = []
        vulnerabilities: list[dict[str, Any]] = []
        for node in _connection_nodes(raw_record.get("objects")):
            entity_type = str(
                node.get("entity_type") or node.get("__typename") or ""
            ).casefold()
            if ("attack" in entity_type and "pattern" in entity_type) or node.get(
                "x_mitre_id"
            ):
                attack_id = str(node.get("x_mitre_id", "")).strip()
                if not attack_id:
                    for reference in _connection_nodes(node.get("externalReferences")):
                        candidate = str(reference.get("external_id", ""))
                        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", candidate):
                            attack_id = candidate
                            break
                if attack_id:
                    techniques.append({"attack_id": attack_id, "name": node.get("name", "")})
            elif "vulnerability" in entity_type:
                cve_id = str(node.get("name", "")).upper().strip()
                if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                    vulnerabilities.append({"cve_id": cve_id})

        markings = []
        for marking in _connection_nodes(raw_record.get("objectMarking")):
            definition = marking.get("definition")
            if definition:
                markings.append(str(definition))

        # Some OpenCTI versions return objectMarking as a direct list while
        # others expose a Relay-style connection. The helper above supports
        # both. Deduplicate linked objects so repeated relationships do not
        # create duplicate report mappings.
        techniques = list(
            {
                str(item["attack_id"]).upper(): {
                    **item,
                    "attack_id": str(item["attack_id"]).upper(),
                }
                for item in techniques
            }.values()
        )
        vulnerabilities = list(
            {str(item["cve_id"]).upper(): item for item in vulnerabilities}.values()
        )
        markings = list(dict.fromkeys(markings))

        normalized: dict[str, Any] = {
            "title": title,
            "summary": raw_record.get("description", ""),
            "source_name": "OpenCTI",
            "published_at": raw_record.get("published"),
            "confidence": raw_record.get("confidence"),
            "marking": ", ".join(markings),
            "metadata": {"opencti_id": report_id, "modified": raw_record.get("modified")},
        }
        if "objects" in raw_record:
            normalized["techniques"] = techniques
            normalized["vulnerabilities"] = vulnerabilities

        return SourceRecord(
            external_id=report_id,
            object_type="threat_report",
            natural_key=title,
            source_updated_at=parse_source_datetime(raw_record.get("modified")),
            raw=dict(raw_record),
            normalized=normalized,
        )
