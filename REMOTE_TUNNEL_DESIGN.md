# Windows SSH reverse tunnel: GX10 and Oracle VPS alternatives

The LAN installer and reverse-tunnel installers serve different network positions. The LAN installer
opens Windows TCP/22 only to `LocalSubnet`. A roaming PC creates an outbound SSH connection to a
hub; the hub receives a TCP/22 listener bound only to its own `127.0.0.1`, then connects back through
that listener. No router port-forward or Windows WAN inbound rule is used.

## Hub addresses

| Hub | Windows PC connects to | Status |
| --- | --- | --- |
| GX10 | `g.hjs.space:1032` | Verified from Osaka; it reached `gx10-0cef`, and its ED25519 key matched the LAN address `192.168.2.93:22`. |
| GX10, same home LAN | `192.168.2.93:22` | Used as a fallback to avoid NAT hairpinning. |
| Osaka VPS | `osaka-v4.hjs.space:22` | Verified from HP-14s end to end. |
| SJ AMD VPS | `sjamd-v4.hjs.space:22` | Not reachable during validation; TCP/22 timed out from GX10 and Osaka. The command is staged but cannot connect until the endpoint is restored and its account is provisioned. |

GX10's public SSH port is **1032**. Port **1034** forwards to the EdgeRouter's own SSH service; it is
not GX10. A PC on the home LAN cannot verify the public GX10 route because the router may not support
NAT loopback. The HP test therefore used the private LAN fallback for GX10. Separately, Osaka verified
the public `g.hjs.space:1032` route and host-key pin.

## Server-side account and key restrictions

GX10 and Osaka each have a dedicated locked `win-tunnel` system account. It has no sudo or group
membership, uses `/usr/sbin/nologin` (GX10) or `/sbin/nologin` (Osaka), and is authorized only by
public key. The per-user effective SSH policy is:

```text
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding remote
AllowStreamLocalForwarding no
PermitOpen none
PermitListen 127.0.0.1:*
GatewayPorts no
PermitTTY no
AllowAgentForwarding no
X11Forwarding no
PermitUserRC no
PermitTunnel no
MaxSessions 0
```

The `PermitListen` wildcard allows the shared account to host different enrolled devices. Every
authorized key narrows it back to one device port:

```text
restrict,port-forwarding,permitlisten="127.0.0.1:<device-port>" ssh-ed25519 <device-public-key> <device-label>
```

`AllowTcpForwarding remote`, `MaxSessions 0`, and `GatewayPorts no` are per-user Match settings; the
existing global SSH policy and existing real user accounts were left unchanged. The authorized-key
files are root-owned and read-only. `sshd -t` and `sshd -T -C user=win-tunnel,...` were run before
reload. The effective policy showed remote forwarding only, no sessions, no TTY, no agent/X11 or
stream-local forwarding, and a loopback-only listener.

The Windows-to-hub tunnel key is separate for GX10, Osaka, and SJ. The GX10-to-Windows administration
key is separate and stays on GX10/Osaka. Windows pins each hub's SSH host key and uses strict host-key
checking. The key/private material is never embedded in a CMD or repository.

## Windows commands

The three one-file CMDs embed the installer and require an elevated Command Prompt. If Windows
OpenSSH Server has not been configured, the remote installer downloads the tested LAN CMD pinned to
commit `d04dfa4ad94ed6e0a005bc64597e9907086304f7`; it initializes `sshd`, installs the seven public
agent keys, disables password login, and scopes inbound SSH to `LocalSubnet`. The reverse tunnel then
uses a second, separate key.

Each hub gets its own SYSTEM startup task and key. The tunnel port is deterministic per Windows
System UUID, in the range 20000–59999; GX10/Osaka may use the same number because they are separate
hosts. A central enrollment process must check for port collisions before authorizing a new key.
For the HP 14s test machine, the assigned port is `51623`.

The CMD outputs the public key and fingerprint only. The destination hub must enroll the key with
the exact port restriction before the connection will authenticate. A machine reachable over a
trusted LAN can have its public key collected and enrolled directly over the existing SSH channel.
A brand-new off-LAN computer has no trusted route to auto-register its public key; server-side
enrollment is a one-time prerequisite, not something solved by embedding a shared private key or
opening an unauthenticated key-upload endpoint.

## HP-14s validation, 2026-11-01

Device: `NB-HP-14s-cf1045tu`, Windows account `huang`, LAN address `192.168.2.83`. Two separate
unattended scheduled tasks ran under SYSTEM:

- GX10 tunnel key fingerprint: `SHA256:Oa396R9zkQt0jyUNnIBt7l8Ef2Z3xCDdPm74sufQu00`.
- Osaka tunnel key fingerprint: `SHA256:y4D1zXtbhIpYN9kF52srONjDs6pr0wrAFUJpsV9PmkE`.
- Both hub listeners were bound to loopback only. SSH through GX10's and Osaka's reverse ports
  returned `NB-HP-14s-cf1045tu` from the Windows SSH server.
- GX10's direct LAN reverse tunnel used `192.168.2.93:22`; it does **not** prove that the PC can
  reach GX10's public endpoint from inside the LAN.
- Osaka separately reached GX10 through `g.hjs.space:1032`; the ED25519 key was identical to the
  GX10 LAN key.
- SJ AMD's SSH endpoint timed out and was not modified. Its CMD and pinned host key are prepared,
  but the hub account cannot be provisioned or tested until the server becomes reachable.

The Windows server host key used for the loopback callback was pinned and the GX10 client key
successfully ran `hostname` through `127.0.0.1:51623`. See the private
[`local-network-tracker` inventory](https://github.com/githubhjs/local-network-tracker) for the
hardware record and exact network identifiers.
