//! STUB — db/sqliteMaintenance.ts (incremental auto-vacuum + free-space reclaim).
use crate::state::AppState;

pub async fn enable_incremental_auto_vacuum(_st: &AppState) {}

pub async fn reclaim_sqlite_free_space(_st: &AppState) {}

pub async fn wait_for_sqlite_maintenance() {}
