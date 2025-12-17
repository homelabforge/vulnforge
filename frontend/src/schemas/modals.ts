import { z } from "zod";
import { dockerImageName } from "./shared";

/**
 * Valid status values for vulnerability management.
 */
export const VULNERABILITY_STATUSES = ["to_fix", "accepted", "ignored"] as const;

/**
 * Schema for vulnerability status update form.
 */
export const vulnerabilityStatusSchema = z.object({
  status: z.enum(VULNERABILITY_STATUSES),
  notes: z.string().optional(),
});

export type VulnerabilityStatusFormData = z.infer<typeof vulnerabilityStatusSchema>;

/**
 * Schema for compliance finding ignore reason.
 * Requires a non-empty reason with minimum length.
 */
export const ignoreReasonSchema = z.object({
  reason: z.string()
    .min(1, "Please provide a reason for ignoring this finding")
    .min(10, "Reason must be at least 10 characters")
    .max(500, "Reason must be less than 500 characters"),
});

export type IgnoreReasonFormData = z.infer<typeof ignoreReasonSchema>;

/**
 * Schema for image scan modal input.
 */
export const imageScanSchema = z.object({
  imageName: dockerImageName,
});

export type ImageScanFormData = z.infer<typeof imageScanSchema>;

/**
 * Validate vulnerability status data.
 */
export function validateVulnerabilityStatus(data: unknown):
  { success: true; data: VulnerabilityStatusFormData } |
  { success: false; error: string } {
  const result = vulnerabilityStatusSchema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return {
    success: false,
    error: result.error.errors[0]?.message || "Invalid vulnerability status",
  };
}

/**
 * Validate ignore reason data.
 */
export function validateIgnoreReason(reason: string):
  { success: true; data: string } |
  { success: false; error: string } {
  const result = ignoreReasonSchema.safeParse({ reason });
  if (result.success) {
    return { success: true, data: result.data.reason };
  }
  return {
    success: false,
    error: result.error.errors[0]?.message || "Invalid reason",
  };
}

/**
 * Validate image name for scanning.
 */
export function validateImageName(imageName: string):
  { success: true; data: string } |
  { success: false; error: string } {
  const result = imageScanSchema.safeParse({ imageName });
  if (result.success) {
    return { success: true, data: result.data.imageName };
  }
  return {
    success: false,
    error: result.error.errors[0]?.message || "Invalid image name",
  };
}
