#!/usr/bin/env bash
# Runs the portable PowerShell 7 source, documentation, and test gates in CI
# order. Windows PowerShell, protected-workspace, and LocalSystem lanes remain
# Windows CI responsibilities.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pwsh_bin="${PWSH_BIN:-pwsh}"
required_pwsh_version="7.6.3"
psa_version="1.25.0"
pester_version="5.8.0"

skip_analyzer="${CI_SKIP_ANALYZER:-}"
skip_tests="${CI_SKIP_TESTS:-}"

runtime_status="NOT_RUN"
secret_status="NOT_RUN"
documentation_status="NOT_RUN"
static_status="NOT_RUN"
analyzer_status="NOT_RUN"
tests_status="NOT_RUN"
overall_status="PASS"
summary_printed=0

print_summary() {
  if [[ "$summary_printed" -eq 1 ]]; then
    return
  fi
  summary_printed=1
  echo
  echo "CI gate summary"
  printf '| %-13s | %-8s |\n' "Gate" "Status"
  printf '| %-13s | %-8s |\n' "-------------" "--------"
  printf '| %-13s | %-8s |\n' "Runtime" "$runtime_status"
  printf '| %-13s | %-8s |\n' "SecretScan" "$secret_status"
  printf '| %-13s | %-8s |\n' "Documentation" "$documentation_status"
  printf '| %-13s | %-8s |\n' "Static" "$static_status"
  printf '| %-13s | %-8s |\n' "Analyzer" "$analyzer_status"
  printf '| %-13s | %-8s |\n' "Tests" "$tests_status"
  printf '| %-13s | %-8s |\n' "Overall" "$overall_status"
}

fail_with_summary() {
  local exit_code="$1"
  overall_status="FAILED"
  print_summary
  exit "$exit_code"
}

if [[ -n "$skip_analyzer" || -n "$skip_tests" ]]; then
  overall_status="PARTIAL"
fi

runtime_status="CHECK"
if ! command -v "$pwsh_bin" >/dev/null 2>&1; then
  echo "pwsh not found. Install PowerShell $required_pwsh_version or set PWSH_BIN to its executable path." >&2
  runtime_status="FAILED"
  fail_with_summary 1
fi

if ! runtime_identity="$("$pwsh_bin" -NoLogo -NoProfile -Command \
  "[string]::Format('{0}|{1}', \$PSVersionTable.PSVersion.ToString(), \$PSVersionTable.PSEdition)")"; then
  echo "Failed to query the PowerShell runtime at: $pwsh_bin" >&2
  runtime_status="FAILED"
  fail_with_summary 1
fi
runtime_identity="${runtime_identity//$'\r'/}"
if [[ "$runtime_identity" != "$required_pwsh_version|Core" ]]; then
  echo "PowerShell runtime drift: expected $required_pwsh_version|Core, got $runtime_identity." >&2
  runtime_status="FAILED"
  fail_with_summary 1
fi
runtime_status="PASS"

if [[ -z "$skip_analyzer" ]]; then
  analyzer_status="SETUP"
  if "$pwsh_bin" -NoProfile -Command "\
if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { \$_.Version -eq '$psa_version' })) {
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  Install-Module -Name PSScriptAnalyzer -RequiredVersion '$psa_version' -Scope CurrentUser -Force
}
Import-Module PSScriptAnalyzer -RequiredVersion '$psa_version' -Force
if ((Get-Module -Name PSScriptAnalyzer).Version.ToString() -cne '$psa_version') {
  throw 'PSScriptAnalyzer version drift.'
}"; then
    analyzer_status="READY"
  else
    analyzer_status="FAILED"
    fail_with_summary 1
  fi
else
  analyzer_status="SKIPPED"
fi

if [[ -z "$skip_tests" ]]; then
  tests_status="SETUP"
  if "$pwsh_bin" -NoProfile -Command "\
if (-not (Get-Module -ListAvailable -Name Pester | Where-Object { \$_.Version -eq '$pester_version' })) {
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  Install-Module -Name Pester -RequiredVersion '$pester_version' -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module Pester -RequiredVersion '$pester_version' -Force
if ((Get-Module -Name Pester).Version.ToString() -cne '$pester_version') {
  throw 'Pester version drift.'
}"; then
    tests_status="READY"
  else
    tests_status="FAILED"
    fail_with_summary 1
  fi
else
  tests_status="SKIPPED"
fi

secret_status="RUN"
if "$pwsh_bin" -NoProfile -File "$root_dir/tools/secret-scan.ps1" -RootPath "$root_dir"; then
  secret_status="PASS"
else
  secret_status="FAILED"
  fail_with_summary 1
fi

documentation_status="RUN"
if "$pwsh_bin" -NoProfile -File "$root_dir/tools/Test-Documentation.ps1" -RootPath "$root_dir"; then
  documentation_status="PASS"
else
  documentation_status="FAILED"
  fail_with_summary 1
fi

static_status="RUN"
if [[ -n "$skip_analyzer" ]]; then
  if "$pwsh_bin" -NoProfile -File "$root_dir/tools/verify.ps1" -RootPath "$root_dir" -SkipAnalyzer; then
    static_status="PASS"
  else
    exit_code=$?
    static_status="FAILED"
    fail_with_summary "$exit_code"
  fi
else
  if "$pwsh_bin" -NoProfile -Command "\
Import-Module PSScriptAnalyzer -RequiredVersion '$psa_version' -Force
& '$root_dir/tools/verify.ps1' -RootPath '$root_dir'
exit \$LASTEXITCODE"; then
    static_status="PASS"
    analyzer_status="PASS"
  else
    exit_code=$?
    static_status="FAILED"
    analyzer_status="FAILED"
    fail_with_summary "$exit_code"
  fi
fi

if [[ -z "$skip_tests" ]]; then
  tests_status="RUN"
  if "$pwsh_bin" -NoProfile -Command "\
Import-Module Pester -RequiredVersion '$pester_version' -Force
Invoke-Pester -Path '$root_dir/tests' -CI -Output Detailed"; then
    tests_status="PASS"
  else
    exit_code=$?
    tests_status="FAILED"
    fail_with_summary "$exit_code"
  fi
fi

print_summary
