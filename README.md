# Windows AI-agent SSH bootstrap

An idempotent PowerShell bootstrap for Josh's device fleet. It enables key-only SSH access to a
Windows device so Codex, Claude Code, or another authorized agent on GX10 can administer it over a
trusted LAN/VPN.

## Security defaults

- Installs Microsoft's Windows OpenSSH Server capability.
- Handles first install by starting `sshd` once to let Windows create
  `%ProgramData%\ssh\sshd_config`, with all known TCP/22 allow rules disabled
  during that initialization; the scoped firewall rule is added after config
  validation.
- Adds seven **public** Ed25519 client keys for GX10, Osaka OPC, San Jose, GCP Oregon, and the home
  and office EdgeRouters, plus the San Jose VPS identity, for the account running the elevated
  script. Private keys stay on their respective hosts. You can still pass other public keys.
- Disables SSH password and keyboard-interactive authentication; requires public-key authentication.
- Restricts SSH logins to that Windows account.
- Allows TCP/22 only from `LocalSubnet` by default, on the Private and Domain firewall profiles.
- Explicitly refuses unrestricted source ranges such as `0.0.0.0/0`, `::/0`, or `Any`.
- Replaces existing exact TCP/22 allow rules with its scoped rule. It checks effective rules for
  broader multi-port/Any-port allows and stops before changing SSH if one could widen access or is
  centrally managed.
- Stops before making changes when an enabled inbound block rule covers SSH, since a block can
  override the new allow rule. This check is deliberately conservative: it stops for any enabled
  inbound block filter that could match TCP/22, regardless of its address or profile scope; review
  the named rule manually rather than deleting it automatically.
- When checking existing TCP/22 rules, also checks the Windows Firewall application and service
  filters. A broad port/address rule limited to another executable, packaged app, or service is not
  mistaken for an SSH rule. Filters are read from the same ActiveStore as the rules. An empty set of
  block rules is handled normally.
- Does **not** create router port forwarding, public DNS, a VPN, or a public SSH service.

Use a private LAN or VPN for remote agents. If a source must be added, specify its observed source IP
or a narrow CIDR. Do not expose TCP/22 to the public internet.

## Run it

Open **PowerShell as Administrator** on the Windows device. Download and inspect the script first:

```powershell
$url = 'https://raw.githubusercontent.com/githubhjs/windows-ai-ssh-bootstrap/main/bootstrap-ssh.ps1'
$script = Join-Path $env:TEMP 'bootstrap-ssh.ps1'
Invoke-WebRequest -Uri $url -OutFile $script
Unblock-File -Path $script
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
notepad $script
```

If PowerShell reports that script execution is disabled, run it from that same elevated window
after setting the process-scoped policy above. This applies only to the current PowerShell process;
it does not change the machine or user execution policy. For a script already saved as
`C:\temp\bootstrap-ssh.ps1`, the two commands are:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
& 'C:\temp\bootstrap-ssh.ps1'
```

Do not use `Unrestricted` or change `LocalMachine` policy for this setup. If Group Policy overrides
the process setting, stop and ask the device administrator rather than trying to bypass that policy.
The script requires an elevated shell. It uses the seven embedded infrastructure public keys by
default, so there is no paste prompt. This public repository is personalized for Josh's devices:
running it authorizes holders of those matching private keys to sign in to the configured Windows
account. Do not run it on someone else's computer.

For the easiest one-file setup, download [`bootstrap-ssh.cmd`](bootstrap-ssh.cmd), open **Command
Prompt as Administrator** in its folder, and run `bootstrap-ssh.cmd`. It contains a compressed copy
of the PowerShell implementation, checks elevation and execution-policy Group Policy overrides,
then extracts to a temporary `.ps1` and runs only that PowerShell process with `-ExecutionPolicy
Bypass`. It removes the temporary file afterward. It stops if MachinePolicy or UserPolicy is
configured; it does not try to evade organization policy. Regenerate it from the source PS1 with
`python scripts/build-single-file.py` after changing the PowerShell implementation.

The two-file alternative is `run-bootstrap-ssh.cmd` beside `bootstrap-ssh.ps1`; it applies the same
checks but requires both files to stay together.

For a single download, get [`dist/windows-ai-ssh-bootstrap.zip`](dist/windows-ai-ssh-bootstrap.zip),
extract it, then run `run-bootstrap-ssh.cmd` from an elevated Command Prompt in the extracted folder.
The archive contains both launch options, the PowerShell implementation, and these instructions.

The bootstrap automatically installs GX10, Osaka OPC, San Jose, GCP Oregon, and both EdgeRouter
client public keys. No private keys are copied. A Windows-host-generated key is not appropriate for
inbound agent access: the Windows machine is the SSH server, while those machines are SSH clients.
The firewall still defaults to `LocalSubnet`; remote hosts need an existing VPN/reverse-tunnel path
or a separately configured narrow source range to reach TCP/22.

## Reverse tunnel for roaming or off-LAN PCs

Use a separate reverse-tunnel command when an authorized PC must remain reachable while it is away
from the home LAN. It first configures Windows OpenSSH Server with the same seven public client keys
and a `LocalSubnet` inbound rule, then creates a separate passphrase-free Ed25519 **client** key for
the selected hub. The private key is stored under `C:\ProgramData\ssh\win-tunnel`, owned by SYSTEM,
and readable only by SYSTEM. Public host-key pins are readable by SYSTEM and Administrators so an
elevated rerun can safely refresh them. A SYSTEM startup task reconnects after network changes and Windows
restarts. The remote command creates no router forwarding or public inbound firewall rule.

Download and run one CMD as Administrator, based on the hub you want this PC to call:

- [`bootstrap-ssh-remote-gx10.cmd`](bootstrap-ssh-remote-gx10.cmd) — public endpoint `g.hjs.space:1032`; on the home LAN it first tries `192.168.2.93:22` to avoid NAT loopback.
- [`bootstrap-ssh-remote-osaka.cmd`](bootstrap-ssh-remote-osaka.cmd) — `osaka-v4.hjs.space:22`.
- [`bootstrap-ssh-remote-sjamd.cmd`](bootstrap-ssh-remote-sjamd.cmd) — `sjamd-v4.hjs.space:22` (the SJ SSH endpoint was unreachable during the 2026-11-01 validation; the command will wait and retry).

Each hub gets its own key and scheduled task. The tunnel port is derived deterministically from the
device's Windows System UUID into 20000–59999; the port is an identifier, not a secret. The server
must enroll that device's public key with an exact `permitlisten="127.0.0.1:<port>"` restriction
before the tunnel can authenticate. The CMD prints only the public key and its fingerprint; it never
prints or uploads the private key. On a PC that is already reachable over the LAN, the administrator
can retrieve that public key through the existing trusted SSH path and enroll it directly without
asking the PC owner to copy it. A brand-new off-LAN PC still needs this one-time server-side key
enrollment through a trusted channel.

GX10 is port **1032**. Port **1034** is the EdgeRouter SSH mapping, not GX10. From a LAN PC, do not
use the public GX10 endpoint as proof of connectivity: NAT hairpinning may fail. The GX10 endpoint
and host-key pin were verified from the Osaka VPS; the HP 14s tunnel was tested to GX10's private
LAN address and separately to Osaka. See [`REMOTE_TUNNEL_DESIGN.md`](REMOTE_TUNNEL_DESIGN.md) for
server restrictions, test evidence, and the SJ AMD blocker.

On completion, it prints a **safe-to-share connection handoff** with hostname, SSH username, active
network profile, IPv4 addresses and interface names, SSH service status, authorized key labels, and
ready-to-run GX10 SSH commands. It does not print private keys or passwords. Public-profile networks
are flagged because the default firewall rule only covers Private and Domain profiles.

```powershell
# Optional: replace the default GX10 key with another client public key.
& $script -AuthorizedKeyPath 'C:\path\to\agents.pub'
```

The default source range is `LocalSubnet`. To allow a client on another private/VPN network, pass
its exact source IP or a narrow CIDR:

```powershell
& $script -AuthorizedKeyPath 'C:\path\to\agents.pub' -AllowedRemoteAddress @('192.168.2.93', '10.20.0.0/24')
```

If the target already has a locally managed exact TCP/22 rule that can match `sshd`, the script
disables that rule and replaces it with the requested source/profile scope. This prevents the old
rule from continuing to allow SSH from `Any`. It refuses to modify centrally managed exact rules,
and stops for broader multi-port rules or matching inbound block rules because those need separate
review.

For multiple agent keys in one file, use `-AuthorizedKeyPath 'C:\path\to\agents.pub'`.

## Verify from the allowed client

```sh
ssh <windows-user>@<windows-ip> hostname
```

For diagnostics on Windows, check `Get-Service sshd`, the `AIAgent-OpenSSH-Limited` firewall rule,
and `C:\ProgramData\ssh\sshd_config`. The script creates a timestamped config backup before
editing it. Re-run the same command to update the key or allowed sources. Centrally managed
firewall policies may still add separate rules and should be reviewed by the device administrator.
Scope comparison is deliberately conservative and textual; semantically equivalent but differently
written IP/CIDR ranges may require resolving the conflicting rule manually.

If a previous run installed the OpenSSH capability but stopped at “OpenSSH configuration was not
found”, download and run the latest `bootstrap-ssh.cmd` again. The current script handles this
first-start initialization itself; do not manually paste keys or create the config file.

## Access the script

- Repository: <https://github.com/githubhjs/windows-ai-ssh-bootstrap>
- Raw script: <https://raw.githubusercontent.com/githubhjs/windows-ai-ssh-bootstrap/main/bootstrap-ssh.ps1>

Review the script before running it. This project does not contain device credentials, private SSH
keys, passwords, or host-specific network details.

## Limitations

- Run from an elevated PowerShell session with administrator rights and internet access to the
  Microsoft capability source.
- The script configures only the current account. Other Windows accounts are intentionally not enabled.
- Firewall defaults assume local/VPN access on Private or Domain profiles. Public-profile access
  requires explicitly passing `-FirewallProfile Public` and a narrow source address.
- Remote access may require a VPN or an existing private tunnel. This script intentionally does not
  alter routers, NAT, DNS, or Cloudflare settings.
- Reverse-tunnel commands require the hub's dedicated `win-tunnel` account and a server-side
  per-device public-key enrollment. Do not run the remote CMD on an untrusted PC; the enrolled hub
  key grants that PC only its assigned loopback listener.
