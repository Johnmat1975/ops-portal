# Setup guide

## 1. Download

Download the installer for your computer from the [Releases](../../releases) page, plus `SHA256SUMS.txt`.

## 2. Check the download

The installers aren't code-signed yet, so check that the file you have is the one that was published. Compare its SHA-256 hash with the line for that file in `SHA256SUMS.txt`:

- **Mac (Terminal):** `shasum -a 256 "Liongard Ops Portal-<version>-universal.dmg"`
- **Windows (PowerShell):** `Get-FileHash "Liongard Ops Portal Setup <version>.exe"`

If the hashes don't match, don't install it.

## 3. Install

### Mac

1. Open the `.dmg` and drag **Liongard Ops Portal** into **Applications**. It runs on Apple Silicon and Intel Macs.
2. The first time, **right-click the app and choose Open**, then click **Open** again. macOS asks because the app isn't signed with an Apple developer certificate yet.

If macOS says the app is damaged or can't be checked, **don't work around the warning.** Download it again and check the hash.

### Windows

1. Run **Liongard Ops Portal Setup <version>.exe**.
2. If Windows SmartScreen says it protected your PC, click **More info**, then **Run anyway**. It appears because the installer isn't code-signed yet.

## 4. Create a read-only access key in Liongard

The app only reads data, but a key with fewer rights is safer if it's ever exposed.

1. In Liongard, use (or create) a user with **read-only** access to the environments you want to see.
2. Signed in as that user, create an **access key** under your account settings in **API keys**.
3. Keep the access key and secret to hand for the next step.

Each person should use their own key. Don't share keys.

## 5. Connect

The app starts empty. There's no client data in it until you connect.

1. Enter your Liongard instance: the part before `.app.liongard.com`, for example `us1`, `eu1` or `au1`.
2. Enter the access key and secret, then click **Connect**. The key is tested before it's saved, and it's encrypted with your operating system's keychain on your own computer.
3. Pick a client (a Liongard environment). The pages unlock.

## 6. Set up your MSP (optional)

Open **Settings** to add:

- your MSP's **name and logo**, used on every report cover;
- your **currency** and **seat prices**, used for licence costs;
- your own **domains and account names**, so the app can tell your accounts from the client's;
- **defaults for new clients**: coverage policy, compliance target and region, and when devices and accounts count as stale.

## Using it

- Each page is pulled once and kept on your computer. Click **Refresh** to update it from Liongard.
- **Export** gives you a PDF executive summary, a full technical report, an HTML snapshot, or CSV for any table.
- **Present** switches to a client-safe view for meetings. Press **Esc** to leave it.
- Every page has a **How this page is built** section listing exactly what it reads from Liongard.

## Disconnecting and removing data

- **Settings › Clear cached client data** deletes every client page saved on your computer. Your key, statuses and remediation list stay.
- **Settings › Remove saved key** disconnects the app and also deletes every saved client page.
- Client data is deleted automatically 30 days after its last refresh (7, 30 or 90 days in Settings).

## Questions

Contact your Liongard representative.
