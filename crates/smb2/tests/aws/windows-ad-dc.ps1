<powershell>
# Unattended Windows AD DC for smb2's Kerberos integration test.
# Advances one stage per boot via marker files; each reboot is an , which makes EC2Launch v2 reboot and run this again.
$ErrorActionPreference = 'Continue'
$dir = 'C:\smb2setup'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
function Log($m) { Add-Content -Path "$dir\log.txt" -Value "$(Get-Date -Format s) $m" }
Start-Transcript -Path "$dir\transcript-$(Get-Date -Format yyyyMMddHHmmss).txt" -Append | Out-Null
# Known admin password every boot, so the setup can be inspected over SMB (C$) without console access.
net user Administrator 'Smb2Admin!2026' | Out-Null
Log "boot: user-data running as $(whoami)"

# Firewall: SMB and Kerberos reachable whatever profile the NIC lands in.
if (-not (Get-NetFirewallRule -DisplayName 'smb2-test' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'smb2-test' -Direction Inbound -Protocol TCP -LocalPort 88,445 -Action Allow -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName 'smb2-test-udp' -Direction Inbound -Protocol UDP -LocalPort 88 -Action Allow -Profile Any | Out-Null
}

if (-not (Test-Path "$dir\stage0")) {
    Log 'stage0: rename to SMB2DC'
    New-Item "$dir\stage0" | Out-Null
    Rename-Computer -NewName 'SMB2DC' -Force
    # EC2Launch v2 reboots and re-runs this script on exit code 3010; Restart-Computer would end it for good.
    exit 3010
}

if (-not (Test-Path "$dir\stage1")) {
    Log 'stage1: install AD DS and promote'
    New-Item "$dir\stage1" | Out-Null
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
    Import-Module ADDSDeployment
    Install-ADDSForest -DomainName 'test.local' -DomainNetbiosName 'TEST' `
        -SafeModeAdministratorPassword (ConvertTo-SecureString 'Dsrm!Pass2026' -AsPlainText -Force) `
        -InstallDns -Force -NoRebootOnCompletion:$true
    Log "stage1: promotion returned $?"
    exit 3010
}

if (-not (Test-Path "$dir\stage2")) {
    Log 'stage2: waiting for AD'
    for ($i = 0; $i -lt 60; $i++) {
        try { Get-ADDomain -ErrorAction Stop | Out-Null; break } catch { Start-Sleep 10 }
    }
    New-ADUser -Name 'smbtest' -SamAccountName 'smbtest' -UserPrincipalName 'smbtest@test.local' `
        -AccountPassword (ConvertTo-SecureString 'Kerberos!Test1' -AsPlainText -Force) `
        -Enabled $true -PasswordNeverExpires $true
    Log "stage2: user created: $?"
    New-Item -ItemType Directory -Force -Path 'C:\testshare' | Out-Null
    icacls 'C:\testshare' /grant 'TEST\smbtest:(OI)(CI)F' | Out-Null
    New-SmbShare -Name 'testshare' -Path 'C:\testshare' -FullAccess 'TEST\smbtest' | Out-Null
    Log "stage2: share created: $?"
    New-Item "$dir\stage2" | Out-Null
    Copy-Item "$dir\log.txt" 'C:\testshare\setup-log.txt'
    Log 'stage2: done'
}
</powershell>
<persist>true</persist>
