# VaultBase Security Dashboard

The **VaultBase Security Dashboard** serves as the user-facing security control center.

## Purpose & Scope

- **Active Sessions**: View, inspect, and revoke live browser/extension sessions in real-time.
- **Trusted Devices**: Manage registered laptops, phones, and browser instances.
- **Biometric Profiles**: Manage enrolled biometric templates (face registration status).
- **Security Audit Logs**: Chronological log of all authentication events, device challenges, and IP addresses.

## Architecture

- **Framework**: React / Vite SPA.
- **Communication**: Communicates with the VaultBase internal backend security endpoints.
- **Authentication**: Authenticated via VaultBase session credentials.
