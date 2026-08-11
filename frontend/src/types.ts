export interface ApiError {
  message: string;
  code?: number;
  is_integrity: boolean;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
}

export interface DbStatus {
  db_id: string;
  operation_count: number;
  merkle_root: string;
  logical_clock: string[];
  latest_snapshot_id?: number;
  snapshot_merkle_root?: string;
  device_count: number;
  self_device_id: string;
  self_public_key: string;
  key_version: number;
  format_version: number;
  bootstrapped: boolean;
}

export interface DeviceInfo {
  device_id: string;
  public_key: string;
  trusted: boolean;
  approved_by?: string;
  created_at: number;
}

export interface OperationSummary {
  sequence: number;
  device_id: string;
  hash: string;
  parent_count: number;
  clock: string[];
}