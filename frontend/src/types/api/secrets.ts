export interface Secret {
  id: number;
  scan_id: number;
  rule_id: string;
  category: string;
  title: string;
  severity: string;
  match: string;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  code_snippet: string | null;
  layer_digest: string | null;
  status: string;
  notes: string | null;
  redacted?: boolean;
  created_at: string;
  updated_at: string | null;
}

export interface SecretListItem extends Secret {
  container_name: string;
}

export interface SecretSummary {
  total_secrets: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  affected_containers: number;
  top_categories: Record<string, number>;
}
