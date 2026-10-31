Windows AI SSH bootstrap bundle (personalized for Josh's devices)

Easiest: open Command Prompt as Administrator in this extracted folder and run:
  bootstrap-ssh.cmd

bootstrap-ssh.cmd is self-contained. It includes the PowerShell implementation and writes it to a
unique temporary .ps1 only while running, then deletes that temporary file. It bypasses PowerShell
ExecutionPolicy only for those processes; it does not modify persistent policy. It stops on a
MachinePolicy or UserPolicy override. Do not bypass organization policy.

Alternative: run-bootstrap-ssh.cmd uses the separate bootstrap-ssh.ps1 beside it.

The bootstrap automatically authorizes GX10's public Ed25519 client key; no paste is needed. Its
private key remains on GX10. Running this personalized script authorizes GX10 to sign in to the
configured Windows account. Default firewall source is LocalSubnet; no router or internet-facing
SSH is configured.
