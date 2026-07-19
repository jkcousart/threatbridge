from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

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


class OpenCtiReportsAdapter(IntegrationAdapter):
    adapter_key = "opencti-reports"
    supported_object_types = ("threat_report",)
    configuration_schema = {
        "required": ["base_url"],
        "properties": {
            "base_url": {"type": "string"},
            "graphql_url": {"type": "string"},
            "page_size": {"type": "integer", "minimum": 1},
            "query": {"type": "string"},
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
        return str(context.configuration.get("graphql_url") or f"{base_url}/graphql")

    def _token(self, context: SyncContext) -> str:
        token = str(context.secrets.get("token") or context.secrets.get("value") or "").strip()
        if not token:
            raise ValueError("OpenCTI secret must contain token")
        return token

    def _request(self, context: SyncContext, variables: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = request_json(
            self._endpoint(context),
            method="POST",
            headers={"Authorization": f"Bearer {self._token(context)}"},
            json_body={
                "query": str(context.configuration.get("query") or DEFAULT_QUERY),
                "variables": dict(variables),
            },
            timeout=int(context.configuration.get("timeout_seconds", 60)),
        )
        errors = payload.get("errors")
        if errors:
            raise ValueError(f"OpenCTI GraphQL returned errors: {errors}")
        return payload

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        payload = self._request(context, {"first": 1, "after": None})
        reports = payload.get("data", {}).get("reports", {})
        return {
            "ok": True,
            "records_returned": len(reports.get("edges", [])),
            "has_next_page": bool(reports.get("pageInfo", {}).get("hasNextPage")),
        }

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        payload = self._request(
            context,
            {
                "first": int(context.configuration.get("page_size", 100)),
                "after": cursor.get("after") or None,
            },
        )
        reports = payload.get("data", {}).get("reports", {})
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
