export interface Container {
  id: number;
  name: string;
  image: string;
  image_tag: string;
  image_id: string;
  is_running: boolean;
  is_my_project: boolean;
  total_vulns: number;
  fixable_vulns: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  last_scan_date: string | null;
  scanner_coverage: number | null;
  dive_efficiency_score: number | null;
  dive_inefficient_bytes: number | null;
  dive_image_size_bytes: number | null;
  dive_layer_count: number | null;
  dive_analyzed_at: string | null;
  created_at: string;
  updated_at: string;
}
