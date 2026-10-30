# Liongard Ops Portal

A desktop app for MSPs that turns your Liongard data into one place to run each client: what to fix first, security and coverage gaps, compliance evidence, licence true-ups, renewals and inspector health. It reads the Liongard API directly with your own access key.

- **Read-only.** The app only reads from Liongard. It never changes anything there.
- **Your data stays with you.** Client data is kept on your computer, encrypted keys and all, and is only ever sent to your own Liongard instance.
- **Works with any stack.** It finds which inspectors you use and fills every page from whichever tools each client runs.

## Download

Get the latest installers from the [Releases](../../releases) page:

| Platform | File |
|---|---|
| macOS (Apple Silicon and Intel) | `Liongard Ops Portal-<version>-universal.dmg` |
| Windows 10 and 11 (64-bit) | `Liongard Ops Portal Setup <version>.exe` |

Each release also has `SHA256SUMS.txt`, so you can check your download before installing. See the [setup guide](SETUP.md).

> The installers aren't code-signed yet, so macOS and Windows show a warning the first time you open the app. The [setup guide](SETUP.md) explains what to expect and how to check the download.

## Get started

1. Install the app (see [SETUP.md](SETUP.md)).
2. In Liongard, create an access key for a **read-only** user.
3. Open the app, enter your instance (the part before `.app.liongard.com`, for example `us1`) and the access key and secret, then click **Connect**.
4. Pick a client. Every page unlocks.

## What's in it

The home page groups the pages by job.

| Group | Pages |
|---|---|
| **Today** | **Overview** (every area for the client, worst first) · **Action plan** (fixes ranked by risk, with owner, effort and ticket text) · **Change pulse** (real configuration changes, routine churn filtered out) · **Inspector health** (failing, stale or unscheduled inspectors) |
| **Security** | **Identity & access** (admins, MFA gaps, leavers, stale accounts, user access review) · **Stack coverage** (RMM, AV/EDR and backup on every device) · **Email & domains** (SPF, DKIM, DMARC, certificates) · **Cyber security** (exposures and MITRE ATT&CK v20.0 coverage) |
| **QBR & commercial** | **Compliance** (technical-control evidence for Cyber Essentials, CIS, PCI DSS, HIPAA, NIS2, DORA, NIST CSF, ISO 27001, Essential Eight, POPIA and cyber insurance) · **Licence reconciliation** (seats bought against seats used, licences per person with costs, a true-up for client sign-off) · **Lifecycle & renewals** · **AI usage** |
| **Estate & tools** | **Network & firmware** · **Customer stack** · **Lookup** (everything about a person, device or domain) · **Wallboard** (for the service-desk screen) |

Also:

- **Present mode** shows a client-safe view for QBRs: internal pages and controls are hidden.
- **Exports:** PDF executive summaries and full reports with your own logo, HTML snapshots, CSV for every table and calendar files for renewals.
- **Settings:** your MSP's name and logo, currency, seat prices, default coverage policy and data retention.

The pages show technical evidence from Liongard. They're leads for a person to check, not a compliance certification or proof of an attack.

## How your data is protected

- Your access key is tested before it's saved, encrypted with your operating system's keychain, and only ever sent to `https://<instance>.app.liongard.com`.
- Client data pulled from Liongard is kept on your computer for 30 days after its last refresh (7, 30 or 90 days in Settings), then deleted. You can clear it at any time.
- Removing your key deletes every client page saved on your computer.
- A source that couldn't be read shows as "unknown", never as an all-clear.

## Build it yourself

The app's source code is in `src/`. To run it from source or build your own installers, see [BUILDING.md](BUILDING.md).

## Releases

See [CHANGELOG.md](CHANGELOG.md) for what's new in each version.

## Support

For questions or problems, contact your Liongard representative.

Copyright © Liongard, Inc.
