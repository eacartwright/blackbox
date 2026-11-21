# Code signing

Status: **not signed yet.** `bbx.exe`, `bbx-agent.exe` and the setup are unsigned, so
Windows shows "Windows protected your PC" (More info > Run anyway) and some antivirus or
EDR products may block or quarantine them. Research below is from 2026-11-21; prices change,
so check them before buying.

## What signing does and doesn't fix

- **Fixes:** the "Unknown publisher" label, tampering detection, and most antivirus / EDR
  blocks (they trust signed binaries far more). Needed before deploying to client machines
  through Intune or similar.
- **Doesn't fix right away:** SmartScreen. A new signature has no reputation, so the warning
  still appears until enough people have installed it. Since 2024 an **EV certificate no
  longer skips this** either, so EV isn't worth its extra cost.

## Options, cheapest first

| Option | Cost | Notes |
|---|---|---|
| **Azure Artifact Signing** (was Trusted Signing) | Monthly subscription; Basic tier includes 5,000 signatures/month. Was about $10/month; confirm on the [pricing page](https://azure.microsoft.com/pricing/details/artifact-signing/) | **Recommended.** Microsoft holds the key; no token, no yearly renewal. Billing starts when the account is created. Eligibility (individuals in some countries, established organizations) has changed over time; check it first. |
| OV certificate from Sectigo / Comodo | From about $219/year via resellers | Key must be on a hardware token or the CA's cloud signing service (since June 2023). Certificates issued after 2026-03-01 last at most 460 days. Avoid "bring your own cloud HSM" options: they add a $500 to $1,500 attestation fee. |
| OV certificate from DigiCert | About $438/year | Same rules as above, higher price. |
| EV certificate | More again | No longer bypasses SmartScreen; skip. |
| SignPath Foundation | Free | Only for open-source projects (public repository). |

## How it fits this project

Sign in this order, all with SHA-256 and an RFC 3161 timestamp (so signatures stay valid
after the certificate expires):

1. `target\release\bbx.exe` and `target\release\bbx-agent.exe`, **before** Inno Setup packs
   them.
2. The setup exe and its uninstaller: give Inno Setup a `SignTool` (Tools > Configure Sign
   Tools, or `ISCC /S"name=command"`) and add `SignTool=name` plus `SignedUninstaller=yes` to
   `[Setup]` in `installer\blackbox.iss`.

`scripts\build-installer.ps1` is the place for step 1: after `cargo build`, run `signtool` on
both exes when signing is configured, and skip it otherwise so unsigned dev builds keep
working.

With Artifact Signing the command looks like this (install the Windows SDK's `signtool` and
Microsoft's Artifact Signing client tools; check flags against Microsoft's current docs):

```powershell
signtool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 `
  /dlib "<path>\Azure.CodeSigning.Dlib.dll" /dmdf signing-metadata.json `
  target\release\bbx.exe target\release\bbx-agent.exe
```

`signing-metadata.json` names the account endpoint, the signing account and the certificate
profile. It holds no secret; sign-in uses Azure credentials (`az login` locally, a service
principal or federated identity in CI). Never commit credentials.

With an OV certificate on a token or cloud service, the command is the same `signtool sign
/fd SHA256 /tr <CA timestamp URL> /td SHA256` with the CA's own options instead of `/dlib`.

Check the result:

```powershell
signtool verify /pa /v dist\BlackBox-Setup-0.1.0.exe
```

## Sources

- [Microsoft: code signing options for Windows apps](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Azure Artifact Signing pricing](https://azure.microsoft.com/pricing/details/artifact-signing/)
- [SSL.com OV code signing](https://www.ssl.com/certificates/code-signing/buy/), [eSigner pricing](https://ssl.com/guide/esigner-pricing-for-code-signing/)
- [SSL Dragon code signing](https://www.ssldragon.com/ssl-certificates/code-signing/), [CheapSSLSecurity DigiCert](https://cheapsslsecurity.com/symantec/codesigningcertificate.html)
