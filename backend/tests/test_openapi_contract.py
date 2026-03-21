"""OpenAPI contract tests — guard against regression to generic dict schemas.

These tests assert that specific endpoints reference named Pydantic component
schemas in the OpenAPI spec.  They will fail if anyone replaces a typed
``response_model`` with ``dict`` and regenerates.
"""

import pytest

from app.main import app

# Map each endpoint to its expected component schema name.
EXPECTED_SCHEMAS: dict[tuple[str, str], str] = {
    ("/api/v1/image-compliance/scan", "post"): "ImageScanTriggerResponse",
    ("/api/v1/image-compliance/scan-all", "post"): "ImageScanAllTriggerResponse",
    ("/api/v1/image-compliance/current", "get"): "ImageScanCurrentStatus",
    ("/api/v1/image-compliance/summary", "get"): "ImageComplianceSummaryResponse",
    ("/api/v1/image-compliance/images", "get"): "ImageComplianceImageEntry",
    ("/api/v1/image-compliance/findings/{image_name}", "get"): "ImageComplianceFindingResponse",
    ("/api/v1/image-compliance/findings/{finding_id}/ignore", "post"): "ImageFindingIgnoreResponse",
    (
        "/api/v1/image-compliance/findings/{finding_id}/unignore",
        "post",
    ): "ImageFindingUnignoreResponse",
    ("/api/v1/image-compliance/scans/history", "get"): "ImageComplianceScanHistoryEntry",
}

# Endpoints whose 200 response is an array (list[...]).
ARRAY_ENDPOINTS: set[tuple[str, str]] = {
    ("/api/v1/image-compliance/images", "get"),
    ("/api/v1/image-compliance/findings/{image_name}", "get"),
    ("/api/v1/image-compliance/scans/history", "get"),
}


def _ids() -> list[str]:
    return [f"{m.upper()} {p}" for (p, m) in EXPECTED_SCHEMAS]


@pytest.mark.parametrize(
    ("path_method", "expected_name"),
    EXPECTED_SCHEMAS.items(),
    ids=_ids(),
)
def test_image_compliance_endpoint_has_typed_schema(
    path_method: tuple[str, str],
    expected_name: str,
) -> None:
    """Each image-compliance endpoint must reference a named component schema."""
    path, method = path_method
    schema = app.openapi()
    resp_schema = schema["paths"][path][method]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    ref_suffix = f"#/components/schemas/{expected_name}"

    if path_method in ARRAY_ENDPOINTS:
        assert resp_schema.get("type") == "array", (
            f"{method.upper()} {path}: expected array schema, got {resp_schema}"
        )
        assert resp_schema["items"].get("$ref", "").endswith(ref_suffix), (
            f"{method.upper()} {path}: items.$ref should end with {ref_suffix}, "
            f"got {resp_schema['items']}"
        )
    else:
        assert resp_schema.get("$ref", "").endswith(ref_suffix), (
            f"{method.upper()} {path}: $ref should end with {ref_suffix}, got {resp_schema}"
        )
