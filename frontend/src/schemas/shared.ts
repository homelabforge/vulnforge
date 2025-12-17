import { z } from "zod";

/**
 * Safely parse a string to a number, returning undefined if invalid.
 * Handles empty strings, null, undefined, and NaN cases.
 */
export function safeParseInt(value: unknown, defaultValue?: number): number | undefined {
  if (value === "" || value === undefined || value === null) {
    return defaultValue;
  }
  const num = typeof value === "number" ? value : parseInt(String(value), 10);
  return isNaN(num) ? defaultValue : num;
}

/**
 * Safely parse a string to a float, returning undefined if invalid.
 */
export function safeParseFloat(value: unknown, defaultValue?: number): number | undefined {
  if (value === "" || value === undefined || value === null) {
    return defaultValue;
  }
  const num = typeof value === "number" ? value : parseFloat(String(value));
  return isNaN(num) ? defaultValue : num;
}

/**
 * Zod schema for coercing a value to a number with safe NaN handling.
 * Returns undefined for invalid values.
 */
export const coerceToNumber = z.preprocess(
  (val) => {
    if (val === "" || val === undefined || val === null) return undefined;
    const num = typeof val === "number" ? val : parseFloat(String(val));
    return isNaN(num) ? undefined : num;
  },
  z.number().optional()
);

/**
 * Create a Zod schema that coerces to number with a default value.
 * Useful for settings that should never be undefined.
 */
export function coerceToNumberWithDefault(defaultValue: number) {
  return z.preprocess(
    (val) => {
      if (val === "" || val === undefined || val === null) return defaultValue;
      const num = typeof val === "number" ? val : parseFloat(String(val));
      return isNaN(num) ? defaultValue : num;
    },
    z.number()
  );
}

/**
 * Create a Zod schema for integers with min/max bounds and a default.
 */
export function integerWithBounds(min: number, max: number, defaultValue: number) {
  return z.preprocess(
    (val) => {
      if (val === "" || val === undefined || val === null) return defaultValue;
      const num = typeof val === "number" ? val : parseInt(String(val), 10);
      if (isNaN(num)) return defaultValue;
      // Clamp to bounds
      return Math.max(min, Math.min(max, num));
    },
    z.number().int().min(min).max(max)
  );
}

/**
 * Zod schema for optional URL validation.
 * Accepts empty strings (converts to undefined).
 */
export const optionalUrl = z.preprocess(
  (val) => (val === "" ? undefined : val),
  z.string().url().optional()
);

/**
 * Zod schema for URL validation that allows empty strings.
 * Returns the string as-is (for fields that can be empty).
 */
export const urlOrEmpty = z.string().refine(
  (val) => {
    if (val === "") return true;
    try {
      new URL(val);
      return true;
    } catch {
      return false;
    }
  },
  { message: "Invalid URL format" }
);

/**
 * Basic cron expression validation.
 * Validates 5-part cron expressions (minute hour day month weekday).
 */
export const cronExpression = z.string().refine(
  (val) => {
    if (!val) return false;
    // Basic validation: 5 space-separated parts
    const parts = val.trim().split(/\s+/);
    if (parts.length !== 5) return false;
    // Each part should be a valid cron token (number, *, ranges, etc.)
    const cronPartPattern = /^(\*|[0-9]+(-[0-9]+)?(\/[0-9]+)?)(,(\*|[0-9]+(-[0-9]+)?(\/[0-9]+)?))*$/;
    return parts.every((part) => cronPartPattern.test(part));
  },
  { message: "Invalid cron expression. Expected format: '0 2 * * *' (minute hour day month weekday)" }
);

/**
 * Zod schema for JSON array strings (validates it's parseable JSON array).
 */
export const jsonArrayString = z.string().refine(
  (val) => {
    if (val === "" || val === "[]") return true;
    try {
      const parsed = JSON.parse(val);
      return Array.isArray(parsed);
    } catch {
      return false;
    }
  },
  { message: "Must be a valid JSON array" }
);

/**
 * Zod schema for valid HTTP header names.
 * Header names must be alphanumeric with hyphens, starting with a letter.
 * Examples: X-Authentik-Username, Content-Type, Authorization
 */
export const httpHeaderName = z.string().refine(
  (val) => {
    if (val === "") return true; // Allow empty for optional fields
    // RFC 7230: Header names are tokens (alphanumeric + !#$%&'*+-.^_`|~)
    // We use a stricter pattern: letters, digits, and hyphens, starting with a letter
    return /^[A-Za-z][A-Za-z0-9-]*$/.test(val);
  },
  { message: "Invalid header name. Use letters, numbers, and hyphens (e.g., X-Custom-Header)" }
);

/**
 * Zod schema for Docker image name validation.
 * Supports: image, image:tag, registry/image, registry/image:tag, registry:port/image:tag
 * Examples: nginx, nginx:latest, docker.io/library/nginx:1.25, ghcr.io/org/image:v1.0
 */
export const dockerImageName = z.string().refine(
  (val) => {
    if (val === "") return false; // Image name is required
    // Docker image name pattern:
    // - Optional registry (hostname with optional port)
    // - Optional namespace/path segments
    // - Image name
    // - Optional tag or digest
    const imagePattern = /^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?::[0-9]+)?\/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*\/)*[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[a-zA-Z0-9][a-zA-Z0-9._-]*)?(?:@sha256:[a-f0-9]{64})?$/;
    return imagePattern.test(val);
  },
  { message: "Invalid Docker image name. Examples: nginx, nginx:latest, ghcr.io/org/image:v1.0" }
);

/**
 * Enhanced cron expression validation with range checking.
 * Validates 5-part cron expressions with proper value ranges:
 * - Minute: 0-59
 * - Hour: 0-23
 * - Day of month: 1-31
 * - Month: 1-12
 * - Day of week: 0-7 (0 and 7 are both Sunday)
 */
export const enhancedCronExpression = z.string().refine(
  (val) => {
    if (!val) return false;
    const parts = val.trim().split(/\s+/);
    if (parts.length !== 5) return false;

    const ranges = [
      { min: 0, max: 59 },  // minute
      { min: 0, max: 23 },  // hour
      { min: 1, max: 31 },  // day of month
      { min: 1, max: 12 },  // month
      { min: 0, max: 7 },   // day of week
    ];

    return parts.every((part, index) => {
      const range = ranges[index];
      // Handle wildcards
      if (part === "*") return true;

      // Handle step values (*/5, 0-30/5)
      const [valuePart, step] = part.split("/");
      if (step !== undefined) {
        const stepNum = parseInt(step, 10);
        if (isNaN(stepNum) || stepNum < 1) return false;
      }

      const baseValue = valuePart === "*" ? "*" : valuePart;
      if (baseValue === "*") return true;

      // Handle comma-separated values
      const values = baseValue.split(",");
      return values.every((v) => {
        // Handle ranges (e.g., 1-5)
        if (v.includes("-")) {
          const [start, end] = v.split("-").map(Number);
          return !isNaN(start) && !isNaN(end) &&
                 start >= range.min && start <= range.max &&
                 end >= range.min && end <= range.max &&
                 start <= end;
        }
        // Handle single values
        const num = parseInt(v, 10);
        return !isNaN(num) && num >= range.min && num <= range.max;
      });
    });
  },
  { message: "Invalid cron expression. Format: 'minute(0-59) hour(0-23) day(1-31) month(1-12) weekday(0-7)'" }
);

/**
 * Schema for API key objects in auth configuration.
 */
export const apiKeyObjectSchema = z.object({
  key: z.string().min(8, "API key must be at least 8 characters"),
  name: z.string().min(1, "API key name is required"),
  admin: z.boolean().optional().default(false),
});

/**
 * Schema for validating JSON string containing API keys array.
 */
export const apiKeysJsonString = z.string().refine(
  (val) => {
    if (val === "" || val === "[]") return true;
    try {
      const parsed = JSON.parse(val);
      if (!Array.isArray(parsed)) return false;
      // Validate each key object
      return parsed.every((item) => {
        const result = apiKeyObjectSchema.safeParse(item);
        return result.success;
      });
    } catch {
      return false;
    }
  },
  { message: 'Invalid API keys format. Expected: [{"key": "...", "name": "...", "admin": true/false}]' }
);

/**
 * Schema for basic auth user objects.
 */
export const basicAuthUserSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password_hash: z.string().refine(
    (val) => /^\$2[aby]?\$\d{1,2}\$.{53}$/.test(val),
    { message: "Password hash must be in bcrypt format" }
  ),
  admin: z.boolean().optional().default(false),
});

/**
 * Schema for validating JSON string containing basic auth users array.
 */
export const basicAuthUsersJsonString = z.string().refine(
  (val) => {
    if (val === "" || val === "[]") return true;
    try {
      const parsed = JSON.parse(val);
      if (!Array.isArray(parsed)) return false;
      // Validate each user object
      return parsed.every((item) => {
        const result = basicAuthUserSchema.safeParse(item);
        return result.success;
      });
    } catch {
      return false;
    }
  },
  { message: 'Invalid users format. Expected: [{"username": "...", "password_hash": "$2b$...", "admin": true/false}]' }
);
