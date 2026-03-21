/**
 * useSettingsForm - Manages a group of settings as a single state object
 * with auto-save integration.
 *
 * Replaces the pattern of N individual useState calls + manual useAutoSave
 * with a single hook that handles initialization, updates, and serialization.
 */

import { useCallback, useState } from "react";
import { useAutoSave } from "./useAutoSave";

/** Field definition for a setting. */
export interface SettingsFieldDef {
  /** Settings key (e.g., "ntfy_enabled") */
  key: string;
  /** Type determines how the value is read from settingsMap and serialized */
  type: "bool" | "string";
  /** Default value if not present in settingsMap */
  defaultValue: string | boolean;
  /**
   * For booleans: "truthy" means the setting defaults to true unless explicitly "false".
   * "falsy" means it defaults to false unless explicitly "true".
   * Defaults to "truthy" if omitted.
   */
  boolDefault?: "truthy" | "falsy";
}

type ValuesRecord = Record<string, string | boolean>;

interface UseSettingsFormReturn {
  /** Current values as a flat record */
  values: ValuesRecord;
  /** Update a single field */
  set: (key: string, value: string | boolean) => void;
  /** Update a boolean field */
  setBool: (key: string, value: boolean) => void;
  /** Update a string field */
  setText: (key: string, value: string) => void;
}

function readField(
  settingsMap: Record<string, string>,
  field: SettingsFieldDef,
): string | boolean {
  const raw = settingsMap[field.key];
  if (field.type === "bool") {
    if (raw === undefined || raw === null) return field.defaultValue;
    const boolDefault = field.boolDefault ?? "truthy";
    return boolDefault === "truthy" ? raw !== "false" : raw === "true";
  }
  return raw ?? (field.defaultValue as string);
}

function buildInitialValues(
  settingsMap: Record<string, string>,
  fields: SettingsFieldDef[],
): ValuesRecord {
  const values: ValuesRecord = {};
  for (const field of fields) {
    values[field.key] = readField(settingsMap, field);
  }
  return values;
}

function serializeToPayload(
  values: ValuesRecord,
  fields: SettingsFieldDef[],
): Record<string, string> {
  const payload: Record<string, string> = {};
  for (const field of fields) {
    const val = values[field.key];
    payload[field.key] = typeof val === "boolean" ? val.toString() : (val as string);
  }
  return payload;
}

/**
 * Manage a group of settings with auto-save.
 *
 * @param settingsMap - Current settings from the API
 * @param fields - Field definitions (key, type, default)
 * @param onSave - Callback to save changed settings
 * @param enabled - Whether auto-save is active
 */
export function useSettingsForm(
  settingsMap: Record<string, string>,
  fields: SettingsFieldDef[],
  onSave: (payload: Record<string, string>) => void,
  enabled: boolean = true,
): UseSettingsFormReturn {
  const [values, setValues] = useState<ValuesRecord>(() =>
    buildInitialValues(settingsMap, fields),
  );

  const set = useCallback((key: string, value: string | boolean) => {
    setValues((prev: ValuesRecord) => ({ ...prev, [key]: value }));
  }, []);

  const setBool = useCallback((key: string, value: boolean) => {
    setValues((prev: ValuesRecord) => ({ ...prev, [key]: value }));
  }, []);

  const setText = useCallback((key: string, value: string) => {
    setValues((prev: ValuesRecord) => ({ ...prev, [key]: value }));
  }, []);

  useAutoSave(
    () => serializeToPayload(values, fields),
    onSave,
    [values],
    enabled,
  );

  return { values, set, setBool, setText };
}
