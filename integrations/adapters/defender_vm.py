from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

from .base import IntegrationAdapter, PullBatch, SourceRecord, SyncContext
from .datetime_utils import parse_source_datetime
from .http_client import request_json


class DefenderVmAdapter(IntegrationAdapter):
    adapter_key = "microsoft-defender-vm"
    supported_object_types = ("software_installation", "vulnerability_finding")
    configuration_schema = {
        "required": ["resource", "base_url"],
        "properties": {
            "resource": {"enum": ["software_inventory", "vulnerabilities"]},
            "base_url": {"type": "string"},
            "page_size": {"type": "integer", "minimum": 1},
            "scope": {"type": "string"},
        },
    }
    display_name = "Microsoft Defender Vulnerability Management"
    description = "Imports paged software inventory or per-device vulnerability assessments."
    configuration_example = {
        "resource": "vulnerabilities",
        "page_size": 50000,
        "base_url": "https://api.security.microsoft.com",
    }

    ENDPOINTS = {
        "software_inventory": "/api/machines/SoftwareInventoryByMachine",
        "vulnerabilities": "/api/machines/SoftwareVulnerabilitiesByMachine",
    }
    DEFAULT_SCOPE = "https://api.securitycenter.microsoft.com/.default"

    def _resource(self, context: SyncContext) -> str:
        resource = str(context.configuration.get("resource", "vulnerabilities"))
        if resource not in self.ENDPOINTS:
            raise ValueError(
                f"Unsupported Defender VM resource {resource}; choose {', '.join(self.ENDPOINTS)}"
            )
        return resource

    def _token(self, context: SyncContext) -> str:
        access_token = str(context.secrets.get("access_token", "")).strip()
        if access_token:
            return access_token
        tenant_id = str(context.secrets.get("tenant_id", "")).strip()
        client_id = str(context.secrets.get("client_id", "")).strip()
        client_secret = str(context.secrets.get("client_secret", "")).strip()
        if not all((tenant_id, client_id, client_secret)):
            raise ValueError(
                "Defender secret must contain access_token or tenant_id, client_id, "
                "and client_secret"
            )
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        token_response = request_json(
            token_url,
            method="POST",
            form_body={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": str(context.configuration.get("scope", self.DEFAULT_SCOPE)),
            },
            timeout=int(context.configuration.get("timeout_seconds", 30)),
        )
        token = str(token_response.get("access_token", "")).strip()
        if not token:
            raise ValueError("Microsoft identity platform response did not contain access_token")
        return token

    def _initial_url(self, context: SyncContext, *, page_size: int | None = None) -> str:
        base_url = str(
            context.configuration.get("base_url", "https://api.security.microsoft.com")
        ).rstrip("/")
        resource = self._resource(context)
        size = page_size or int(context.configuration.get("page_size", 50000))
        return f"{base_url}{self.ENDPOINTS[resource]}?{urlencode({'pageSize': size})}"

    def _get_page(self, context: SyncContext, url: str) -> Mapping[str, Any]:
        return request_json(
            url,
            headers={"Authorization": f"Bearer {self._token(context)}"},
            timeout=int(context.configuration.get("timeout_seconds", 60)),
            retries=int(context.configuration.get("retries", 3)),
        )

    def test_connection(self, context: SyncContext) -> Mapping[str, Any]:
        payload = self._get_page(context, self._initial_url(context, page_size=1))
        return {
            "ok": True,
            "resource": self._resource(context),
            "records_returned": len(payload.get("value", [])),
            "has_next_page": bool(payload.get("@odata.nextLink")),
        }

    def pull(self, context: SyncContext, cursor: Mapping[str, Any]) -> PullBatch:
        url = str(cursor.get("next_url") or self._initial_url(context))
        payload = self._get_page(context, url)
        records = payload.get("value", [])
        if not isinstance(records, list):
            raise ValueError("Defender API response value must be an array")
        next_url = str(payload.get("@odata.nextLink", "")).strip()
        return PullBatch(
            records=records,
            next_cursor={"next_url": next_url} if next_url else {},
            has_more=bool(next_url),
            snapshot_complete=not next_url,
            source_metadata={"resource": self._resource(context)},
        )

    def normalize(self, context: SyncContext, raw_record: Mapping[str, Any]) -> SourceRecord:
        resource = self._resource(context)
        if resource == "software_inventory":
            return self._normalize_software(raw_record)
        return self._normalize_vulnerability(raw_record)

    def _normalize_software(self, raw_record: Mapping[str, Any]) -> SourceRecord:
        device_id = str(raw_record.get("deviceId", "")).strip()
        vendor = str(raw_record.get("softwareVendor", "")).strip()
        product = str(raw_record.get("softwareName", "")).strip()
        version = str(raw_record.get("softwareVersion", "")).strip()
        if not all((device_id, product)):
            raise ValueError("Defender software record requires deviceId and softwareName")
        external_id = "|".join((device_id, vendor, product, version))
        first_seen = parse_source_datetime(raw_record.get("softwareFirstSeenTimestamp"))
        end_of_support = raw_record.get("endOfSupportDate")
        return SourceRecord(
            external_id=external_id,
            object_type="software_installation",
            natural_key=product,
            source_updated_at=first_seen,
            raw=dict(raw_record),
            normalized={
                "asset_external_id": device_id,
                "hostname": raw_record.get("deviceName", ""),
                "os_platform": raw_record.get("osPlatform", ""),
                "vendor": vendor,
                "product": product,
                "version": version,
                "first_seen_at": raw_record.get("softwareFirstSeenTimestamp"),
                "end_of_support_at": end_of_support,
                "metadata": {
                    "rbac_group_name": raw_record.get("rbacGroupName"),
                    "number_of_weaknesses": raw_record.get("numberOfWeaknesses"),
                    "disk_paths": raw_record.get("diskPaths", []),
                    "registry_paths": raw_record.get("registryPaths", []),
                    "end_of_support_status": raw_record.get("endOfSupportStatus"),
                },
            },
        )

    def _normalize_vulnerability(self, raw_record: Mapping[str, Any]) -> SourceRecord:
        device_id = str(raw_record.get("deviceId", "")).strip()
        cve_id = str(raw_record.get("cveId", "")).strip().upper()
        vendor = str(raw_record.get("softwareVendor", "")).strip()
        product = str(raw_record.get("softwareName", "")).strip()
        version = str(raw_record.get("softwareVersion", "")).strip()
        if not all((device_id, cve_id)):
            raise ValueError("Defender vulnerability record requires deviceId and cveId")
        external_id = str(raw_record.get("id", "")).strip() or "|".join(
            (device_id, cve_id, vendor, product, version)
        )
        last_seen = parse_source_datetime(raw_record.get("lastSeenTimestamp"))
        return SourceRecord(
            external_id=external_id,
            object_type="vulnerability_finding",
            natural_key=cve_id,
            source_updated_at=last_seen,
            raw=dict(raw_record),
            normalized={
                "asset_external_id": device_id,
                "hostname": raw_record.get("deviceName", ""),
                "os_platform": raw_record.get("osPlatform", ""),
                "cve_id": cve_id,
                "severity": raw_record.get("vulnerabilitySeverityLevel", "unknown"),
                "cvss_score": raw_record.get("cvssScore"),
                "exploitability": raw_record.get("exploitabilityLevel", ""),
                "vendor": vendor,
                "product": product,
                "version": version,
                "status": "open",
                "first_seen_at": raw_record.get("firstSeenTimestamp"),
                "last_seen_at": raw_record.get("lastSeenTimestamp"),
                "recommendation": raw_record.get("recommendedSecurityUpdate", ""),
                "metadata": {
                    "rbac_group_name": raw_record.get("rbacGroupName"),
                    "recommendation_reference": raw_record.get("recommendationReference"),
                    "recommended_security_update_id": raw_record.get(
                        "recommendedSecurityUpdateId"
                    ),
                    "security_update_available": raw_record.get("securityUpdateAvailable"),
                    "disk_paths": raw_record.get("diskPaths", []),
                    "registry_paths": raw_record.get("registryPaths", []),
                },
            },
        )
