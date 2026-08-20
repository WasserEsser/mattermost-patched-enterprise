#!/bin/bash
# Verifies that a patched Mattermost binary accepts the fake license and
# that enterprise features are active. Used by the CI workflow for both
# the nightly new-release run and the pull-request version matrix.
#
# Usage: license-check.sh <app_dir> <version_label> <port>
#   app_dir      directory containing bin/mattermost (patched), bin/mmctl,
#                i18n/ and templates/ (i.e. a full extraction or the
#                /mattermost dir copied out of the docker image)
#   version_label used for the database name and log output
#   port         HTTP port for the test server (must be free)
#
# Requires: docker (postgres container), curl. For arm64 binaries the
# runner needs QEMU/binfmt (docker/setup-qemu-action).
set -uo pipefail

APP_DIR="$1"
VERSION="$2"
PORT="$3"
: "${PG_PORT:=5432}"

fail() {
  echo "ERROR: $*"
  exit 1
}

[ -x "$APP_DIR/bin/mattermost" ] || fail "no patched binary at $APP_DIR/bin/mattermost"
[ -x "$APP_DIR/bin/mmctl" ] || fail "no mmctl at $APP_DIR/bin/mmctl"
[ -d "$APP_DIR/i18n" ] || fail "missing i18n/ in $APP_DIR"

# The server needs a config file to exist; env overrides provide the settings.
# Tarballs and the docker image ship one, but make sure anyway.
mkdir -p "$APP_DIR/config"
[ -f "$APP_DIR/config/config.json" ] || echo '{}' > "$APP_DIR/config/config.json"

# The repo's license file (invalid signature, accepted only by patched binaries)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LICENSE_FILE="$SCRIPT_DIR/../license.mattermost-license"
cp "$LICENSE_FILE" "$APP_DIR/license" || fail "cannot copy license file"

DB_NAME="mm_$(echo "$VERSION" | tr -c "[:alnum:]" "_" | tr "A-Z" "a-z")"

# Shared postgres container (started once per job, reused across versions)
docker start mm-license-pg >/dev/null 2>&1 || docker run -d --name mm-license-pg \
  -e POSTGRES_USER=mmuser -e POSTGRES_PASSWORD=mmuser -e POSTGRES_DB=mattermost \
  -p 127.0.0.1:${PG_PORT}:5432 postgres:16-alpine >/dev/null || fail "cannot start postgres"
PG_UP=0
for i in $(seq 1 30); do
  docker exec mm-license-pg pg_isready -U mmuser >/dev/null 2>&1 && { PG_UP=1; break; }
  sleep 1
done
[ "$PG_UP" = "1" ] || fail "postgres did not become ready"

# Each version needs its own database (migrations are version-specific)
docker exec mm-license-pg dropdb -U mmuser --if-exists "$DB_NAME" >/dev/null 2>&1
docker exec mm-license-pg createdb -U mmuser "$DB_NAME" >/dev/null 2>&1 || fail "cannot create database $DB_NAME"

# Config via environment overrides - works across all supported versions
export MM_SERVICESETTINGS_LISTENADDRESS="127.0.0.1:${PORT}"
export MM_SERVICESETTINGS_SITEURL="http://127.0.0.1:${PORT}"
export MM_SERVICESETTINGS_ENABLESETUPWIZARD=false
export MM_SERVICESETTINGS_ENABLESECURITYFIXALERT=false
export MM_SERVICESETTINGS_ENABLELOCALMODE=true
export MM_SERVICESETTINGS_LOCALMODESOCKETLOCATION="/var/tmp/mattermost_local.socket"
export MM_SQLSETTINGS_DRIVERNAME=postgres
export MM_SQLSETTINGS_DATASOURCE="postgres://mmuser:mmuser@127.0.0.1:${PG_PORT}/${DB_NAME}?sslmode=disable&connect_timeout=10"
export MM_FILESETTINGS_DIRECTORY="$APP_DIR/data"
export MM_LOGSETTINGS_ENABLECONSOLE=true
export MM_LOGSETTINGS_CONSOLELEVEL=ERROR

cd "$APP_DIR" || exit 1
mkdir -p data
rm -f /var/tmp/mattermost_local.socket
bin/mattermost server > server.log 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null; sleep 2; rm -f /var/tmp/mattermost_local.socket; }
trap cleanup EXIT

UP=0
for i in $(seq 1 90); do
  curl -s -m 2 "http://127.0.0.1:${PORT}/api/v4/system/ping" 2>/dev/null | grep -q '"status":"OK"' && { UP=1; break; }
  sleep 2
done
if [ "$UP" != "1" ]; then
  echo "ERROR: server did not start within the timeout (port ${PORT})"
  tail -5 server.log
  exit 1
fi

./bin/mmctl --local user create --username admin --password "Admin@123456" \
  --email admin@example.com --system-admin --email-verified >/dev/null 2>&1
./bin/mmctl --local license remove >/dev/null 2>&1
UPLOAD=$(./bin/mmctl --local license upload license 2>&1)
API=$(curl -s -m 10 "http://127.0.0.1:${PORT}/api/v4/license/client?format=old")

echo "  upload: ${UPLOAD}"
echo "  client api: $(echo "$API" | head -c 100)"

echo "$UPLOAD" | grep -q "Uploaded license file" || fail "license upload failed"
echo "$API" | grep -qF 'IsLicensed":"true' || fail "license is not active"
echo "$API" | grep -qE '"(Cluster|Compliance|DataRetention)":"true' || fail "enterprise features not enabled"
echo "LICENSE OK: ${VERSION}"