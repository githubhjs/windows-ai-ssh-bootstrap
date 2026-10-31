@echo off
setlocal
set "BOOTSTRAP_BUNDLE_FILE=%~f0"
set "BOOTSTRAP_HUB=osaka"

rem Validate policy and administrator elevation, then unpack the embedded script.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $policy=Get-ExecutionPolicy -List; $policy | Format-Table -AutoSize; if (@($policy | Where-Object { $_.Scope -in @('MachinePolicy','UserPolicy') -and $_.ExecutionPolicy -ne 'Undefined' }).Count -gt 0) { Write-Error 'Execution policy is enforced by Group Policy. Ask the device administrator; no bypass was attempted.'; exit 3 }; $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $principal=[Security.Principal.WindowsPrincipal]::new($identity); if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error 'Open Command Prompt as Administrator and run this file again.'; exit 2 }; $raw=[IO.File]::ReadAllText($env:BOOTSTRAP_BUNDLE_FILE,[Text.Encoding]::ASCII); $markerMatch=[regex]::Match($raw,'(?m)^::BEGIN_PS_PAYLOAD::
?$'); if (-not $markerMatch.Success) { Write-Error 'Embedded bootstrap payload marker was not found.'; exit 4 }; $payload=($raw.Substring($markerMatch.Index+$markerMatch.Length) -replace '\s',''); if ($payload -notmatch '^[A-Za-z0-9+/]+={0,2}$') { Write-Error 'Embedded payload contains invalid Base64 characters; download the latest CMD file again.'; exit 4 }; try { $bytes=[Convert]::FromBase64String($payload) } catch { Write-Error 'Embedded payload is malformed; download the latest CMD file again.'; exit 4 }; $inputStream=[IO.MemoryStream]::new($bytes); $gzip=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress); $reader=[IO.StreamReader]::new($gzip,[Text.Encoding]::UTF8); $source=$reader.ReadToEnd(); $temp=Join-Path $env:TEMP ('bootstrap-ssh-remote-'+[guid]::NewGuid().ToString('N')+'.ps1'); $code=1; try { [IO.File]::WriteAllText($temp,$source,[Text.UTF8Encoding]::new($false)); & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $temp -Hub $env:BOOTSTRAP_HUB; $code=$LASTEXITCODE } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }; exit $code"
set "RC=%ERRORLEVEL%"
exit /b %RC%

::BEGIN_PS_PAYLOAD::
H4sIAAAAAAACA7Vae3faOhL/n0+hZbMFn8YOkFeTe7KnhNCUNiRcIE1v05xU2ALcGNu15BDuYz/7
zkjyC0iave1yz03B0oxmRj/NSw5pRGfVEoHPdQ+/M8Giapf6DhVBtCBHZENEMTNu1JQP1HNhhA2Y
qFYmD/VaZZNUAk7vKH7hX+nMqSRzuYhcf3Kz8TYebRap+9SfsGptk+zt7m7vJvNdX9xsDGPfZ14v
iAQsXdN0fO4Ke3qz0Y/95oT5omSUShvtKAqipi3cwO9FbMwi5tsMiCoDEYSVUskdk2pKYZA/JKuN
KAiQ87vA9c0eFVOywfz7w14UTED3EyooaMGnn+cwLKQoFUUXRsHY9ZgkKZBLhmVU0vrKA7+spnvB
5KmpJkWhLJil58Oaq1Jddc5POn1QaMEFm203Pl+EzB8M3n6G2RZ7YKAkEo9jX1qBDBkX5tAO274T
AidRzbYg4OIc9nZTWxntm3wfujMWxKLLQYDGbq2WmErKZXsuCAoj1+dMWIPAvmOCW7BGSw7cHB76
bF41UgIBkMnIJQtB+R3CSLGyWgFY1RZNvvDtak4wKZNRII2YiCNfcbCuqCuqmbAGMQGjy1yZkzL4
K/1mUwAP+SNlN6YeZ7nxsetTzwO5U24nLg8DzqqGnvWXMvR8CggAUMkDkVNzjdIaLqD3KRMmSCfQ
jOaZC6eLemqL85Ay+3RO/iQw8Z5F4k0UzMx3gKYCUwT0P6pykxXNOm7We7bABwYISMQ0CuakrM4U
uWML4nIyczkHUBySjeoKUTlnFnVcGLWnzGn6iwRUuJXSgoWJ40DOBOOwZJ7rZ0IlxNxYMtSSXjnw
EjPBBkl5WviImNI7VBV60yEJH6m1DdZ2/Zgt6fKEPrihK3ObjvPIxiWH2wR/BsuUN6q4yeA8GDHf
BNGMChIYKAZCEkxNRIDGLmhhHOafSOHLq+LCQW9GEzyZr6sro/ipmOfoeM2h/BvC3/TMF5jjqJsf
Xdr5zUe4B8j3GA9QN3DY0YJxuZB83HHANK5wGb/wvYUae4pN+8EVFz4YaE4j5w11vTha4jgA4WyB
5gGxWlNm34Gs32VcvuQseu8Hcx8p+RtQ6yiP7XREQfxJGQcsggPY9Nx71oGtj+6pd7Rdy0mYjbeC
2Bdd+nC0/ah07XUWH/DpmQLQY2R9VKre2Ldq8F/9MKdLFh2Nw2xCo/GIUuUcKRrJeL0Cw1XQGStP
Xqj49FqjcRWmDHa2BfjAs3TWHAzbHzvD1sVJ+6efKQh+aw8TQQmYk0lSVEv774LDWeMK1jmnH5XY
D9ARjN0JgN0h03hEUgcpBaAjj/2CoSlaoKcAp1nf5aubMhA0EubAYywk5oABS4fDzJV5ie9bUv9n
agSxMhM904YKyFFCwfEJc4oqbddyKq0E5p8qXbvfv+jL2HZrtR9sFmJmZHUZ55ByGeukWGva7Vop
m4WgIrUSoCg5TdIjK8ExCc5+4QdPGuahyzkkfsCvyZAGw65zy5zG7m79IBseQqaTjDc7MnM1+ww8
DmcAffP0IyTc6eQ0qK6Gh9d/EBkqgU39oGHV915ZDetgu/IL0Zl1o7GEihzFxJp+5RYPqc0ygnpt
O0+SOYnMva6KUVicgPswtcakCZ/W9vnvtFX3Pp106ufD9i4+63R4eNXo0t/v909722E8trun+59O
vr3sXIlu5DbHfo0OTmPx69f3QaW41nVO7ptDKe//b0UjBw9Z/vwgBG5VDfVcIFwUZxeRkNtKydW8
31m3owiBR7dxDeXzrNmltYtvi4vTXkC3P1y9/G3Rrr8Tv+7v7dU7Z9x/2//GP7Xupov+bvS+kjei
LB1/1Iiq/nyuEQfvmt2TZxhRcv1bRlylfCYka8f3xxNn/3Twbessom2n8bHf+7jT8drvxp23dGv7
Q/Plx1fepNHcTY2I3slVGRlW7dfgyeIIvls9SD9sN6SedeX6TjDnOm9bQPEGHrQVR1A5C6jhwLnp
mU/Tpw909Zcua5RUZE35WB3e8fuBx6pPsDuOXU+oacCw6cxc34WcCdsPRhKRVSFTwfoXaqTZDEs/
qNkh3hDKSYGG4FgU+0ADxY4swuiEur5VUQ488Fx7oeuy9gNIJRsI6ikEHC6kEq+rycw/ydWURcy8
GH2FbB6LxFtrYAchRB2IbLDJXQiFrs8UC8wREbf6V1KlYixaWspnMBNCJVSfzKkAiiyZUBJzArFm
Se+UmGihXAyzUHPZkFOMFuQ0CuKQKM6/YMoxWoSUczIH4+i4zJzEAGllmgaza2xJ3JT+Tm/knM3N
DixA5N/hAsxy4kZgKOwd5dseGKIB/n+Si1iY57HnlTa4zKVbNKQj11OoxU3RsMg9N6G+ACsRUx7m
iu6CWCoX/w98ZBpsQWjEPNVpyXzrGYrg5FuVnQEpRRQ1YzENIvd35oCH4c/gQfPY47c0pb+Fcptr
iVBS1066AckvpQ6OEzPXzCID2BNfeItWksvJTtaytSzIWzD1QRx1fC4gLUMcmXACHm8SZOYxvjNz
jTU0SV6jBKf/JH0WcwZ4hf+BI8DyrHkOqZ+SK8L+gBx0/RGg3JGJvNJok4TxCIBLVO9Fs0PjbeJf
M4DaUsN+E45zBOLi6c7tHbEhHUXLbcqzfxbY1BvEI58lzICKzTFt5XhuLTIEQSIVB4gCMnEFZ96Y
OAGkdj7ANUBPQ8kVKJFSh+DyLd3eo/4xoBq3PbyM0F9WpkKE/HBrK6Jza+IKyPTBIJGtUlnLDmZb
6imEgq25grhJXRPjwShhteXUdpwx3aHOwQ5z9liN1mq7I3tvZ/dgnx0c1PZrr/a2azvj/a2UBBlY
dhL1CoKtNiARwcN2t0cqBXoTqEyHhZi5+/YiYyeB1xt8AEuBeYeY8FvpT6tLv8KumuBLdrHtojqE
Chc9DKRd6kPOHYFTT5w/nB4R2IGX9hOXnqP/gOlDj9eTZLPj3wd3zLxioz77FjNs/1xG7uoOmOBX
sPJfNUFJl7Brn0sN8yWrPFC1fPMMwIJYzhAL/whwt2MKyzlkDruqKgQbK+ACM6ssA/PGnWqyrOkG
5/sw6A7AP8cjPbec0FnwrAxcCo2MR1vLctrtFOeVpfs5+04vGhEkO9Ebsiv9jL51yOtl1WB/1IFU
/9detpEGeywBvxcEkhig2tC5GJCPMH/9PBFN2ApQfUlSHZ61sIlQRAlFHNeRvkR7QcBHhJHRW6hI
/HQ79y5r46qTDR5kplrxZSlt66Lbuxy2++fNbtuUe6Ndmo7N+mLBlll1uagCMb8RU5AkDzXPyZfy
lzIxx/BvsjL+buFvvfCXcjk5SXL5YDYImU22HLJly2WeOk/fCTYa80ahqa5sC0mRp8wovTwkcwRT
m3AaUVB1HDFG2loNkba5rUqWFEuJcrdKJvuW5VcbceyifWQroeXOZCDFayTY0u3GLSgZxiCnQgR4
KSe2hWFdXnZOFPmU8qksUrL8thUtQoFJQjiFGP222djdA5fWksLrixJ5XwDBeIpVo+Zh6bXewq/q
9ZA9CKvtg0fB1uHh4eXwzSsLZDxeQHStSqmN5HIid32hWS1fXxQv1Ro1+JCXpHp9jL0yeeEgvfQw
uOz4YrtRRck20Uj/Ijs42ZCJI5dGGEh7rUvnk0eqvBi7kifWB5WBWTd3zforqFUQXU3b05kQflsL
+2QeMBVN22ac92OPYZhgMkdSdzCb+ibCKGXXDxHMIzIxT1goenkzcH0fuM5NMtBns+CeZeybnqfo
0W45AS7mPouqmf5GYgskKhhD8cK8LQo8C8ORQk62hjaJvvRLOOprzu/y6buTqeDA4w24Nz38NG3h
lw6voGcwLxnrbVzN6WaUBk9tEsEhXRZpXqV8lMJztaYLT8yv4HdJ+Uv0xS8bAET1rXTduZCqgoRX
oAluBx6D6lLcg03PHmySlaPSHLQ6HaPUCsKFrkwKsvcGun5UGpyAR4LzI/PuXPhT1Qpog2EUhXoS
swX5CjQ/hN88n1UQ50efRvKSPGvg/KjEz0JDMS3JgyLHF2xpJ3XZdRA5UFI7N7rZA8ELHSH8U8r1
fQo3FyXd9NHJSeonil2XdLS4I7LLm8+DclmRHCz4x5y3LC33hVYvNDG9e/67AYkN0pveYSDveRGI
IVDswMjgeRfGCeQJxgawLlXF4xHBknyANxuwZw62wHRZqbsd7Pt5T9LnCeYQ+qbM8z7fQ2b1OcTf
HH+rNAi2OprEMikpm+dBTzcW4Ksv785QontGVrosx6o5Ycp0HRKM9NhhypG8sEFMRAWaDqwmIncy
kaBYUW6oh8ymkI38OCzJ9wV6uV7WClE2aCK4Og4o/xvkLF2onwEXUOpgI0PXMnAaVGMGRDuDFMsj
b8ENg9/ADobA+12+bo2BHoN/cybA9xfO3JmL99f4fRBSH5zWJxYFYM9u7Ak39FiShnDSmfjgGoA5
LA9LgoKqS3RwcJA+SS4qSRWFSLgCN9eH7eakbpT6bOLC5kZFEYmZdkizG8bkialhkwDLTCyd7oaZ
mXHJ5GaiPMlMtNoA0hcvz5WotP6ipiRLJnANaRq3/uzosgpftDAs0GWGHU/InUAT7Ffiya+++Ps1
AdTB42yVxr9f1LWqA3n9my2JllKtGy3vsw1gqJaPLtMAp895u6gkY6l8l4JUKoVfR0dHRLfDdXWL
ZS08rcjNYpMIWzWtwIPcvbWgfp64DMsc6uOZf4yyFt4sSYXH92YS1Y0lIpW4ewhRiE0E0DZF9rkr
8MwnF0lPGB7RQ7JSEhWn6YoM34DJbTmQ5X4VKZQTAhMektTehRkVzVN3r5B1ldMxw/tpyJ8jJnte
gQ/1mIttPtU6YD7kYR76TONwjZl/YzI3yy2jwV1YeYid7bRVxR4w2ZfdNdDjHpGFJZDscuF98ywG
mrQvqdriKK1sXFAyw0tYjCMhuAd87gVBOKL2nex3kYhx+VIGuoARwzxFNfnUltngZ/R7LlBz/Rfb
cguWTCgAAA==
