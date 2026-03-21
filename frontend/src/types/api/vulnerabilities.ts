/**
 * Vulnerability type definitions.
 * Generated types aliased from OpenAPI.
 *
 * Note: The frontend "Vulnerability" maps to backend VulnerabilitySummary
 * (which includes container_name/container_id from the JOIN).
 */

import type { components } from '../api.generated';

// Generated aliases
export type Vulnerability = components['schemas']['VulnerabilitySummary'];
export type PaginatedVulnerabilities = components['schemas']['PaginatedVulnerabilities'];
export type RemediationGroup = components['schemas']['RemediationGroup'];
