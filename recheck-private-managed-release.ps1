param(
    [string]$Root = "C:\RustDeskDev\src\rustdesk"
)

$ErrorActionPreference = "Stop"

$PrivateEnv = Join-Path $Root "local-managed-build.ps1"
$Release = Join-Path $Root "flutter\build\windows\x64\runner\Release"
$InstallPage = Join-Path $Root "flutter\lib\desktop\pages\install_page.dart"
$ManagedState = Join-Path $env:ProgramData "RustDeskManaged\directory_state.dpapi"

if (-not (Test-Path -LiteralPath $PrivateEnv)) {
    throw "Private build environment file not found."
}
if (-not (Test-Path -LiteralPath $Release)) {
    throw "Release directory not found."
}
if (-not (Test-Path -LiteralPath (Join-Path $Release "rustdesk.exe"))) {
    throw "Release rustdesk.exe not found."
}

# Load private build values into this process without displaying them.
. $PrivateEnv

$RequiredEnv = @(
    "RUSTDESK_INSTALLER_AUTH_SALT_HEX",
    "RUSTDESK_INSTALLER_AUTH_PBKDF2_HEX",
    "RUSTDESK_INSTALLER_AUTH_PBKDF2_ITERATIONS"
)

foreach ($Name in $RequiredEnv) {
    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Required private build variable is missing: $Name"
    }
}

function Convert-HexToBytes {
    param([Parameter(Mandatory=$true)][string]$Hex)

    if (($Hex.Length % 2) -ne 0 -or $Hex -notmatch '^[0-9A-Fa-f]+$') {
        throw "Invalid private verifier hex data."
    }

    $Bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        $Bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $Bytes
}

function Test-ByteSequence {
    param(
        [Parameter(Mandatory=$true)][byte[]]$Haystack,
        [Parameter(Mandatory=$true)][byte[]]$Needle
    )

    if ($Needle.Length -eq 0 -or $Haystack.Length -lt $Needle.Length) {
        return $false
    }

    $First = $Needle[0]
    $Limit = $Haystack.Length - $Needle.Length

    for ($i = 0; $i -le $Limit; $i++) {
        if ($Haystack[$i] -ne $First) { continue }

        $Match = $true
        for ($j = 1; $j -lt $Needle.Length; $j++) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) {
                $Match = $false
                break
            }
        }

        if ($Match) { return $true }
    }

    return $false
}

function Test-FilesContainBytes {
    param(
        [Parameter(Mandatory=$true)][System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory=$true)][byte[]]$Needle
    )

    foreach ($File in $Files) {
        try {
            $Bytes = [IO.File]::ReadAllBytes($File.FullName)
            if (Test-ByteSequence -Haystack $Bytes -Needle $Needle) {
                return $true
            }
        }
        catch {
            throw "Could not inspect release file: $($File.FullName)"
        }
    }

    return $false
}

Write-Host ""
Write-Host "=== PRIVATE MANAGED RELEASE SECURITY RE-CHECK ==="
Write-Host "Read-only audit. No RustDesk launch, server contact, enrollment, or Git operation."
Write-Host ""

$Secure = Read-Host "Enter Server Enrollment Password for local verification" -AsSecureString
$Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)

try {
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)

    if ([string]::IsNullOrEmpty($Password)) {
        throw "Password cannot be blank."
    }

    $Salt = Convert-HexToBytes $env:RUSTDESK_INSTALLER_AUTH_SALT_HEX
    $Expected = Convert-HexToBytes $env:RUSTDESK_INSTALLER_AUTH_PBKDF2_HEX

    [int]$Iterations = 0
    if (-not [int]::TryParse(
        $env:RUSTDESK_INSTALLER_AUTH_PBKDF2_ITERATIONS,
        [ref]$Iterations
    )) {
        throw "Invalid PBKDF2 iteration count."
    }

    if ($Iterations -lt 100000) {
        throw "PBKDF2 iteration count is unexpectedly low."
    }

    $PasswordBytes = [Text.Encoding]::UTF8.GetBytes($Password)
    $Kdf = [Security.Cryptography.Rfc2898DeriveBytes]::new(
        $PasswordBytes,
        $Salt,
        $Iterations,
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )

    try {
        $Derived = $Kdf.GetBytes($Expected.Length)
    }
    finally {
        $Kdf.Dispose()
    }

    $Diff = 0
    for ($i = 0; $i -lt $Expected.Length; $i++) {
        $Diff = $Diff -bor ($Derived[$i] -bxor $Expected[$i])
    }

    $VerifierMatch = ($Diff -eq 0)

    $Files = @(
        Get-ChildItem -LiteralPath $Release -Recurse -File -ErrorAction Stop
    )

    $Utf8Password = [Text.Encoding]::UTF8.GetBytes($Password)
    $Utf16Password = [Text.Encoding]::Unicode.GetBytes($Password)

    $PlainUtf8Found = Test-FilesContainBytes -Files $Files -Needle $Utf8Password
    $PlainUtf16Found = Test-FilesContainBytes -Files $Files -Needle $Utf16Password

    # option_env! values are compiled as strings, so check for the verifier text
    # without displaying it.
    $VerifierAscii = [Text.Encoding]::ASCII.GetBytes(
        $env:RUSTDESK_INSTALLER_AUTH_PBKDF2_HEX
    )
    $SaltAscii = [Text.Encoding]::ASCII.GetBytes(
        $env:RUSTDESK_INSTALLER_AUTH_SALT_HEX
    )

    $VerifierPresent = Test-FilesContainBytes -Files $Files -Needle $VerifierAscii
    $SaltPresent = Test-FilesContainBytes -Files $Files -Needle $SaltAscii

    $UiText = [IO.File]::ReadAllText($InstallPage)
    $SingleLabelCount = ([regex]::Matches(
        $UiText,
        [regex]::Escape("Server Enrollment Password")
    )).Count

    $OldUiAbsent =
        -not $UiText.Contains("Installer authorization password") -and
        -not $UiText.Contains("Directory enrollment password")

    Write-Host ""
    Write-Host ("Entered Server Enrollment Password matches hardened verifier: {0}" -f `
        ($(if ($VerifierMatch) { "PASS" } else { "FAIL" })))

    Write-Host ("Password plaintext absent from Release binaries/files: {0}" -f `
        ($(if (-not $PlainUtf8Found -and -not $PlainUtf16Found) { "PASS" } else { "FAIL" })))

    Write-Host ("Salted PBKDF2 verifier present in Release: {0}" -f `
        ($(if ($VerifierPresent -and $SaltPresent) { "PASS" } else { "FAIL" })))

    Write-Host ("Single Server Enrollment Password UI present: {0}" -f `
        ($(if ($SingleLabelCount -ge 1 -and $OldUiAbsent) { "PASS" } else { "FAIL" })))

    Write-Host ("Managed DPAPI enrollment state absent: {0}" -f `
        ($(if (-not (Test-Path -LiteralPath $ManagedState)) { "PASS" } else { "FAIL" })))

    $AllPass =
        $VerifierMatch -and
        (-not $PlainUtf8Found) -and
        (-not $PlainUtf16Found) -and
        $VerifierPresent -and
        $SaltPresent -and
        ($SingleLabelCount -ge 1) -and
        $OldUiAbsent -and
        (-not (Test-Path -LiteralPath $ManagedState))

    Write-Host ""
    if ($AllPass) {
        Write-Host "HARDENED PRIVATE RELEASE RE-CHECK PASSED"
    }
    else {
        Write-Host "HARDENED PRIVATE RELEASE RE-CHECK FAILED"
        exit 1
    }
}
finally {
    if ($Bstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
    }

    if ($null -ne $Derived) {
        [Array]::Clear($Derived, 0, $Derived.Length)
    }
}
