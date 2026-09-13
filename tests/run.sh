#!/bin/sh
# Backend tests for the behavioural telemetry path and the player risk model.
# Both run against a throwaway SQLite file and never touch the live database.
set -e
here=$(cd "$(dirname "$0")" && pwd)
export ACPDIR="$here/.."
export SCRATCH="${TMPDIR:-/tmp}"
php "$here/behavior_test.php"
php "$here/risk_thresholds_test.php"
php "$here/client_profiles_test.php"
php "$here/report_ingest_test.php"
php "$here/access_control_test.php"
php "$here/report_index_test.php"
php "$here/release_reputation_test.php"
