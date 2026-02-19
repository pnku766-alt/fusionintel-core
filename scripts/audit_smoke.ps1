Set-StrictMode -Version Latest

function Assert-Eq([string]$name, $actual, $expected) {
  if ($actual -ne $expected) {
    throw "ASSERT FAIL [$name] expected=$expected actual=$actual"
  }
}

# Order-insensitive JSON compare (handles null properly)
function Assert-JsonEq([string]$name, $actualObj, $expectedJson) {
  $expectedObj = if ($expectedJson -eq "null") { $null } else { $expectedJson | ConvertFrom-Json }

  # Normalize both sides through JSON serialization to remove ordering noise
  $a = $actualObj   | ConvertTo-Json -Compress -Depth 50
  $e = $expectedObj | ConvertTo-Json -Compress -Depth 50

  if ($a -ne $e) {
    throw "ASSERT FAIL [$name] expected=$e actual=$a"
  }
}

function Test-AuditMatrix-Assert {
  param(
    [string]$Url = "http://127.0.0.1:8000/v1/process",
    [string]$AuditPath = ".\audit.jsonl"
  )

  $payload = @{
    policy = @{
      layer4 = @{ allowed_jurisdictions = @("US"); allowed_residency_classes=@("domestic") }
      layer5 = @{ require_layer4_allow = $false }
      layer6 = @{ include_payload = $false; redact_payload_keys=@() }
    }
    envelope = @{
      artifact_id="a-1"; artifact_type="intel"; producer_layer="layer3"
      payload=@{ k="v"; keep="ok" }
      metadata=@{ m="n" }
      jurisdiction_tags=@{ jurisdiction="US"; residency_class="domestic"; export_control_flags=@(); sanctions_flags=@() }
    }
    options = @{ audit_log_path = $AuditPath }
  }

  $cases = @(
    @{ name="no payload";          include=$false; redact=@();        expected="null" },
    @{ name="payload no redact";   include=$true;  redact=@();        expected='{"k":"v","keep":"ok"}' },
    @{ name="payload redact k";    include=$true;  redact=@("k");     expected='{"keep":"ok"}' },
    @{ name="payload redact keep"; include=$true;  redact=@("keep");  expected='{"k":"v"}' }
  )

  foreach ($c in $cases) {
    $payload.envelope.payload = @{ k="v"; keep="ok" }
    $payload.policy.layer6.include_payload = $c.include
    $payload.policy.layer6.redact_payload_keys = $c.redact

    $res = Invoke-RestMethod -Method Post -Uri $Url -ContentType "application/json" `
      -Body ($payload | ConvertTo-Json -Depth 10)

    Assert-Eq "$($c.name) audit_written" ($res.audit_written.ToString()) "True"

    $last = Get-Content $AuditPath -Tail 1 | ConvertFrom-Json
    Assert-JsonEq "$($c.name) payload_snapshot" $last.payload_snapshot $c.expected

    "PASS: {0}" -f $c.name
  }

  "ALL PASS"
}
