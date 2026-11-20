#!/bin/sh
# One-shot bootstrap for the Docker integration suites (sdk-kit SPEC §8).
#
# OWNED BY THIS REPOSITORY: sdk-kit writes this skeleton once and never overwrites it.
# Runs in the `bootstrap` service of docker/compose.service.yml after `service` is healthy.
# Prepare Casdoor for the tests (init/unseal, users, tokens, streams, buckets ...) and write
# the credentials the tests need to /bootstrap/env with bootstrap_set. Exit non-zero on failure:
# the test containers then never start and compose-run.sh prints this job's log.
# Never print secret values.
set -eu
# shellcheck source=lib.sh
. /scripts/lib.sh

: "${SERVICE_URL:?SERVICE_URL is not set}"

bootstrap_begin

# --- Casdoor: check the admin sign-in, hand the test settings to the suites -------------------
bootstrap_wait_http -t 120 "$SERVICE_URL/api/health"
login=$(wget -q -O - --header "Content-Type: application/json" \
  --post-data "{\"application\":\"app-built-in\",\"organization\":\"built-in\",\"username\":\"admin\",\"password\":\"$CASDOOR_ADMIN_PASSWORD\",\"type\":\"login\"}" \
  "$SERVICE_URL/api/login") || bootstrap_fail "admin sign-in request failed"
case "$login" in
  *'"status": "ok"'*|*'"status":"ok"'*) ;;
  *) bootstrap_fail "admin sign-in was refused" ;;
esac
# Admin operations of the core suites use the admin session.
bootstrap_set GROW_CASDOOR_ADMIN_PASSWORD "$CASDOOR_ADMIN_PASSWORD"
# Full flow suites (test/real-casdoor.*, tests/test_real_casdoor.py, real_casdoor_test.go).
bootstrap_set GROW_CASDOOR_IT_URL "$SERVICE_URL"
bootstrap_set GROW_CASDOOR_IT_ADMIN_PASSWORD "$CASDOOR_ADMIN_PASSWORD"
bootstrap_set GROW_CASDOOR_IT_MAILPIT "http://mailpit:8025"
bootstrap_set GROW_CASDOOR_IT_SMTP_HOST "mailpit"
# -------------------------------------------------------------------------------------------------

bootstrap_commit
