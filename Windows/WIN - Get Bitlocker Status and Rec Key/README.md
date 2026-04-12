# Windows BitLocker Status and Recovery Key Reporter

A professional PowerShell utility designed to audit BitLocker encryption status, retrieve recovery keys, and verify TPM (Trusted Platform Module) health. This script automates the collection of critical security information and exports it to a user-specified text file for documentation and auditing purposes.

## 🚀 Overview

When managing Windows environments, ensuring that BitLocker is active and that recovery keys are properly documented is vital for data protection and disaster recovery. This script streamlines this process by:

- **BitLocker Auditing**: Retrieves detailed encryption status for all BitLocker volumes using `Get-BitLockerVolume` and `manage-bde.exe`.
- **Key Recovery**: Extracts the BitLocker Recovery Key (if applicable) for the system drive (`C:`).
- **TPM Verification**: Checks for the presence and readiness of the Trusted Platform Module (TPM) and provides a full TPM report.
- **Automated Reporting**: Appends all collected data to a structured text report at a path of your choosing.

## 📋 Requirements

- **Operating System**: Windows (with BitLocker and TPM capabilities).
- **Privileges**: **Administrator Rights** are required to access BitLocker information and TPM status.
- **PowerShell**: PowerShell 5.1 or higher.
- **Dependencies**: Uses standard Windows modules (`BitLocker`, `Tpm`).

## 🛠️ Installation

Since this is a standalone PowerShell script, no formal installation is required.

1. **Download the script**: Save `WIN-GetBitLockerStat_RecKey.ps1` to your local machine.
2. **Execution Policy**: Ensure your PowerShell execution policy allows running local scripts. You can set this for the current session using:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   ```

## 📖 How to Use

1. **Open PowerShell as Administrator**: Right-click on PowerShell and select **Run as Administrator**.
2. **Navigate to the script directory**:
   ```powershell
   cd "C:\path\to\your\script"
   ```
3. **Execute the script**:
   ```powershell
   .\WIN-GetBitlockerStat_RecKey.ps1
   ```
4. **Follow the Prompt**:
   - The script will prompt you: `Where would you like to save the report to? (full path!)`.
   - **Important**: You must provide the **full path including the filename and .txt extension**.
   - *Example Input*: `C:\Reports\BitLocker_Audit_Report.txt`

## ⚠️ Important Notes

- **Security Warning**: This script retrieves BitLocker Recovery Keys. The resulting text file will contain sensitive information. **Handle the output file with extreme care** and ensure it is stored in a secure, encrypted location.
- **Automation**: If you wish to automate this script (e.g., via Task Scheduler), you can modify the script to hardcode the `$SaveLOC` variable as described in the script comments.

## 🔍 Output Structure

The generated report contains:
- BitLocker Volume Status
- `manage-bde.exe` detailed status
- BitLocker Recovery Key (if available)
- TPM Presence and Readiness status
- Detailed TPM Report
