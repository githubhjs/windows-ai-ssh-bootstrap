Windows AI SSH bootstrap bundle

Easiest: open Command Prompt as Administrator in this extracted folder and run:
  bootstrap-ssh.cmd

bootstrap-ssh.cmd is self-contained. It includes the PowerShell implementation and writes it to a
unique temporary .ps1 only while running, then deletes that temporary file. It bypasses PowerShell
ExecutionPolicy only for those processes; it does not modify persistent policy. It stops on a
MachinePolicy or UserPolicy override. Do not bypass organization policy.

Alternative: run-bootstrap-ssh.cmd uses the separate bootstrap-ssh.ps1 beside it.

The bootstrap prompts for the connecting agent's SSH PUBLIC key if not passed. Never paste a
private key. Default firewall source is LocalSubnet; no router or internet-facing SSH is configured.
