#!/usr/bin/env bash
# The one place that decides whether a scan result passes. The scan and SARIF
# steps only produce data; this script applies the policy.
#
# Policy (each threshold is UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL or NONE to disable):
#   FAIL_ON_SEVERITY          default CRITICAL  fail on findings at or above it, fixed or not
#   FAIL_ON_FIXABLE_SEVERITY  default HIGH      fail on findings at or above it that have a fixed version
#   Secrets found in the image always fail.
#
# Waivers: an optional ignore file in Trivy's .trivyignore format, one entry per
# line: "<ID> exp:YYYY-MM-DD", with a comment saying why. Every entry must have
# an expiry date. A waiver applies through its date; after that the finding
# blocks again and the gate prints the expired entry.
#
# Usage: gate.sh <trivy.json> [ignore-file]
# Writes the decision as JSON to $GATE_RESULT (default: gate.json next to the
# input), with the image ID and the SHA-256 of the scan it evaluated, so publish
# can check that the decision belongs to the current scan. Any earlier result is
# removed first: a failed or invalid run leaves no gate.json behind.
# Exit codes: 0 pass, 2 policy violation, 1 usage or configuration error.
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  die "usage: $0 <trivy.json> [ignore-file]"
fi
IN="$1"
IGNORE_FILE="${2:-}"
FAIL_ON="${FAIL_ON_SEVERITY:-CRITICAL}"
FAIL_ON_FIXABLE="${FAIL_ON_FIXABLE_SEVERITY:-HIGH}"
RESULT="${GATE_RESULT:-$(dirname "$IN")/gate.json}"
TODAY="${GATE_TODAY:-$(date -u +%Y-%m-%d)}"
rm -f "$RESULT"
require_cmd jq

for setting in FAIL_ON FAIL_ON_FIXABLE; do
  case "${!setting}" in
    UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL | NONE) ;;
    *) die "${setting}_SEVERITY must be one of UNKNOWN LOW MEDIUM HIGH CRITICAL NONE, got '${!setting}'" ;;
  esac
done

[ -s "$IN" ] || die "scan result not found or empty: ${IN}"
jq -e '.SchemaVersion == 2' "$IN" >/dev/null 2>&1 || die "not a Trivy JSON report (schema 2): ${IN}"
input_sha256="$(sha256_of "$IN")"

# Parse the waiver file into a JSON array of {id, expires, line}.
waivers='[]'
if [ -n "$IGNORE_FILE" ] && [ ! -f "$IGNORE_FILE" ]; then
  log "no waiver file at ${IGNORE_FILE}; evaluating without waivers"
  IGNORE_FILE=""
fi
if [ -n "$IGNORE_FILE" ]; then
  lineno=0
  while IFS= read -r raw || [ -n "$raw" ]; do
    lineno=$((lineno + 1))
    fields=()
    read -r -a fields <<<"${raw%%#*}"
    [ "${#fields[@]}" -eq 0 ] && continue
    id="${fields[0]}"
    expires=""
    i=1
    while [ "$i" -lt "${#fields[@]}" ]; do
      case "${fields[$i]}" in
        exp:*) expires="${fields[$i]#exp:}" ;;
        *) die "${IGNORE_FILE}:${lineno}: unexpected '${fields[$i]}' (format: <ID> exp:YYYY-MM-DD)" ;;
      esac
      i=$((i + 1))
    done
    [ -n "$expires" ] || die "${IGNORE_FILE}:${lineno}: ${id} has no expiry; every waiver needs exp:YYYY-MM-DD"
    # Round-trip through strptime/strftime to reject dates such as 2026-02-30.
    jq -en --arg d "$expires" '$d | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$") and (strptime("%Y-%m-%d") | mktime | strftime("%Y-%m-%d")) == $d' >/dev/null 2>&1 \
      || die "${IGNORE_FILE}:${lineno}: invalid date '${expires}' (use YYYY-MM-DD)"
    waivers="$(jq -c --arg id "$id" --arg exp "$expires" --argjson line "$lineno" \
      '. + [{id: $id, expires: $exp, line: $line}]' <<<"$waivers")"
  done <"$IGNORE_FILE"
fi

# shellcheck disable=SC2016 # $today, $waivers etc. are jq variables
run_to_file "$RESULT" jq \
  --arg fail_on "$FAIL_ON" \
  --arg fail_on_fixable "$FAIL_ON_FIXABLE" \
  --arg today "$TODAY" \
  --arg input "$IN" \
  --arg input_sha256 "$input_sha256" \
  --arg ignore_file "$IGNORE_FILE" \
  --argjson waivers "$waivers" '
  def rank: {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "NONE": 99}[.];
  ($fail_on | rank) as $any_min
  | ($fail_on_fixable | rank) as $fix_min
  | (.Metadata.ImageID // null) as $image_id
  | ($waivers | map(select(.expires >= $today))) as $active
  | ($waivers | map(select(.expires < $today))) as $expired
  | ($active | map({key: .id, value: .expires}) | from_entries) as $until
  | [ .Results[]? as $r
      | ( ($r.Vulnerabilities // [])[]
          | {kind: "vulnerability", id: .VulnerabilityID, severity: (.Severity // "UNKNOWN"),
             package: .PkgName, installed: .InstalledVersion, fixed: (.FixedVersion // ""),
             title: (.Title // ""), target: $r.Target} ),
        ( ($r.Secrets // [])[]
          | {kind: "secret", id: .RuleID, severity: (.Severity // "UNKNOWN"),
             package: "", installed: "", fixed: "", title: (.Title // ""),
             target: "\($r.Target):\(.StartLine)"} )
    ]
  | map(. + {reason: (
        if .kind == "secret" then "secret found in image"
        elif (.severity | rank) >= $any_min then "\(.severity), fail on \($fail_on) or above"
        elif .fixed != "" and (.severity | rank) >= $fix_min then "\(.severity) with fix available, fail on fixable \($fail_on_fixable) or above"
        else null end)})
  | map(if .reason != null and $until[.id] != null then . + {waived_until: $until[.id]} else . end)
  | . as $findings
  | ($findings | map(select(.reason != null and .waived_until == null))) as $blocking
  | ($findings | map(select(.waived_until != null))) as $waived
  | {
      decision: (if ($blocking | length) > 0 then "fail" else "pass" end),
      evaluated_on: $today,
      input: $input,
      input_sha256: $input_sha256,
      image_id: $image_id,
      policy: {
        fail_on_severity: $fail_on,
        fail_on_fixable_severity: $fail_on_fixable,
        secrets: "any secret fails",
        ignore_file: (if $ignore_file == "" then null else $ignore_file end)
      },
      counts: (reduce ($findings[] | select(.kind == "vulnerability")) as $f
        ({"CRITICAL": {total: 0, fixable: 0}, "HIGH": {total: 0, fixable: 0},
          "MEDIUM": {total: 0, fixable: 0}, "LOW": {total: 0, fixable: 0},
          "UNKNOWN": {total: 0, fixable: 0}};
         .[$f.severity].total += 1
         | .[$f.severity].fixable += (if $f.fixed != "" then 1 else 0 end))),
      secrets: ($findings | map(select(.kind == "secret")) | length),
      blocking: $blocking,
      waived: $waived,
      expired_waivers: $expired,
      unused_waivers: ($active | map(select(.id as $id | ($waived | map(.id) | index($id)) == null)))
    }
  ' "$IN" || die "could not evaluate ${IN}"

# Human-readable summary on stdout.
jq -r '
  def finding: "  \(.severity | . + (" " * (8 - length))) \(.id) \(if .kind == "secret" then .target else "\(.package) \(.installed)" + (if .fixed != "" then " -> \(.fixed)" else "" end) end)";
  "Policy: fail on \(.policy.fail_on_severity) or above; fail on \(.policy.fail_on_fixable_severity) or above when a fix exists; any secret fails",
  "Waivers: \(.policy.ignore_file // "none") (\(.waived | length) findings waived, \(.expired_waivers | length) expired entries)",
  "",
  "severity   total  fixable",
  (.counts | to_entries[] | "\(.key | . + (" " * (9 - length)))  \(.value.total | tostring | (" " * (5 - length)) + .)  \(.value.fixable | tostring | (" " * (7 - length)) + .)"),
  "secrets    \(.secrets | tostring | (" " * (5 - length)) + .)",
  (if (.blocking | length) > 0 then "", "Blocking findings (\(.blocking | length)):", (.blocking[] | finding + "  [\(.reason)]") else empty end),
  (if (.waived | length) > 0 then "", "Waived findings (\(.waived | length)):", (.waived[] | finding + "  [waived until \(.waived_until)]") else empty end),
  (.expired_waivers[] | "WARN: waiver for \(.id) expired on \(.expires) (line \(.line)); it is no longer applied"),
  (.unused_waivers[] | "WARN: waiver for \(.id) (line \(.line)) matches no blocking finding; consider removing it")
' "$RESULT"

if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
  jq -r '
    (.blocking[:20][] | "::error title=Gate: \(.id)::\(.severity) \(.id) in \(if .kind == "secret" then .target else "\(.package) \(.installed)" end) (\(.reason))"),
    (.expired_waivers[] | "::warning title=Expired waiver::\(.id) expired on \(.expires)")
  ' "$RESULT"
fi

echo
if [ "$(jq -r '.decision' "$RESULT")" = "fail" ]; then
  echo "Gate FAILED (result: ${RESULT})"
  exit 2
fi
echo "Gate PASSED (result: ${RESULT})"
