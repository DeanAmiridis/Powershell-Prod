# Assuming you have already connected via graph. If not, authenticate using the following:
# Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All"

try {
    Select-MgProfile beta -ErrorAction Stop
} catch {
    Write-Verbose "Select-MgProfile not available on this version of Microsoft.Graph."
}

# Get all users with license and sign-in info
$allUsers = Get-MgUser -All -Property `
    "id,displayName,mail,userPrincipalName,assignedLicenses,signInActivity"

# Keep only licensed users
$result = $allUsers |
    Where-Object { $_.assignedLicenses.Count -gt 0 } |
    Select-Object `
        displayName,
        userPrincipalName,
        mail,
        @{Name="IsLicensed";Expression={ $_.assignedLicenses.Count -gt 0 }},
        @{Name="LastInteractiveSignIn";Expression={ $_.signInActivity.lastSignInDateTime }},
        @{Name="LastNonInteractiveSignIn";Expression={ $_.signInActivity.lastNonInteractiveSignInDateTime }}

# Show and export
$result | Format-Table -AutoSize
$result | Export-Csv ".\LicensedUsers_LastSignIn.csv" -NoTypeInformation -Encoding UTF8