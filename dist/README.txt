Windows AI SSH bootstrap bundle (personalized for Josh's devices)

Easiest: open Command Prompt as Administrator in this extracted folder and run:
  bootstrap-ssh.cmd

bootstrap-ssh.cmd is self-contained. It includes the PowerShell implementation and writes it to a
unique temporary .ps1 only while running, then deletes that temporary file. It bypasses PowerShell
ExecutionPolicy only for those processes; it does not modify persistent policy. It stops on a
MachinePolicy or UserPolicy override. Do not bypass organization policy.

Alternative: run-bootstrap-ssh.cmd uses the separate bootstrap-ssh.ps1 beside it.

The bootstrap automatically authorizes seven curated public client keys for GX10, Osaka OPC, San
Jose, GCP Oregon, and the home/office EdgeRouters, plus the San Jose VPS identity. Private keys stay
on their respective hosts. The 49-key union is not used because it includes retired, temporary, and
third-party keys. This personalized script authorizes the listed infrastructure clients. Default
firewall source is LocalSubnet; remote servers need an existing VPN/reverse tunnel or a separate
narrow source rule. No router port-forwarding or internet-facing SSH is configured.

On a first install, Windows may not create %ProgramData%\ssh\sshd_config until sshd starts. The
script temporarily disables known TCP/22 allow rules, starts sshd to generate its default config,
stops the service, then edits and validates the config before adding the restricted firewall rule.

On success, the script prints a safe-to-share connection handoff: hostname, SSH username, network
profiles, IPv4 addresses and interface names, firewall/service status, authorized key labels, and
ready-to-run SSH commands from GX10. It never prints private keys or passwords.
