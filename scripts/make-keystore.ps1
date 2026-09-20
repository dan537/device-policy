# Creates devicepolicy.jks using the password already in keystore.properties.
# Prints nothing sensitive. Idempotent: refuses to overwrite an existing JKS.
$ErrorActionPreference = 'Stop'
$dir = 'C:\phone-guard\dpc'
$jks = Join-Path $dir 'devicepolicy.jks'
$propsFile = Join-Path $dir 'keystore.properties'

if (Test-Path $jks) { Write-Host "keystore already exists at $jks - refusing to overwrite"; exit 0 }
if (-not (Test-Path $propsFile)) { Write-Host "keystore.properties missing"; exit 1 }

$props = @{}
Get-Content $propsFile | ForEach-Object {
    $i = $_.IndexOf('=')
    if ($i -gt 0) { $props[$_.Substring(0, $i)] = $_.Substring($i + 1) }
}
$pw = $props['storePassword']

$tmp = Join-Path $env:TEMP 'keytool-out.txt'
& 'C:\Program Files\Android\openjdk\jdk-21.0.8\bin\keytool.exe' -genkeypair -v `
    -keystore $jks -alias devicepolicy -keyalg RSA -keysize 3072 -validity 10950 `
    -storepass $pw -keypass $pw `
    -dname 'CN=Device Policy, OU=personal, O=dan537, L=UK, C=GB' *> $tmp
$code = $LASTEXITCODE
Remove-Variable pw
Get-Content $tmp | Select-Object -Last 5
Remove-Item $tmp -ErrorAction SilentlyContinue
Write-Host "keytool exit code: $code"
if (Test-Path $jks) { Write-Host "OK: keystore at $jks" } else { Write-Host "FAILED: no jks produced"; exit 1 }
exit $code
