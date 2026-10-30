# Changelog

## 0.6.0

### New

- **Redesigned app.** A client switcher in the top bar (Ctrl K or ⌘K also jumps to any page), a health ribbon for the current client, data age at a glance, and Light, System or Dark themes.
- **New home page.** Same-size tiles grouped by job (Today, Security, QBR & commercial, Estate & tools), in a layout that stays steady when you resize or maximise the window.
- **Present mode.** A client-safe view for QBRs: internal pages and MSP-only controls are hidden, and the Action plan becomes read-only.
- **Products found automatically.** Licence reconciliation adds a row for every inspector a client runs (73 products across RMM, EDR, backup, MDM, firewalls, SaaS and more), with seats in use and, where Liongard has it, seats purchased. A new tool appears after its next refresh. Each row shows the monthly cost of seats in use once you add a price.
- **Licences per person.** Pick anyone to see every licence and device product tied to them (Microsoft 365, training, MFA, AI, RMM, EDR/AV, backup, app control) with a monthly and yearly cost. A shared device is counted once.
- **MITRE ATT&CK v20.0.** The Cyber security matrix now covers 46 techniques, grouped by tactic, with filters.
- **Work done view** on the Action plan for QBRs, and a **Ticketed** status with a reference to paste into your PSA.
- **Currency setting** for seat prices and licence costs.

### Improved

- One alert count across the Wallboard, Overview and Action plan.
- Compliance asks you to set the client's profile before showing results, and never counts a device with no protection data as a pass.
- Prices typed with a decimal comma (12,50) are read correctly.
- PDF executive summaries start with the cover page and leave out empty sections.
- Better keyboard focus, screen-reader labels and colour contrast in both themes.
- AI usage shows Anthropic spend in US dollars, correctly converted from the cost report.
