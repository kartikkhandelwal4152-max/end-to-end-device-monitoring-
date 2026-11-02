# Pilot workflow

1. Back up and migrate the existing database, then perform local admin password recovery as described in MIGRATION_CREDENTIALS.md.
2. Sign in to the dashboard with username `admin` and the initial/recovery password. The dashboard uses sessions, supports authenticator-code login, and revokes sessions on Logout.
3. Select **Set up authenticator**, store the displayed secret in an authenticator app, then enter a current code to enable MFA. Enrollment revokes your session; sign in again with your password and code. Preserve your authenticator backup.
4. Create individual users through the authenticated `/api/users` endpoint. Supported roles: viewer, analyst, administrator. User-management and fleet-investigation APIs are present; not every administrative workflow has a dedicated dashboard screen.
5. Register devices, securely transfer their separate device tokens, and run the agent only on authorized endpoints. Rotate previously exposed secrets before reconnecting agents.
6. Browser history/window-title collection is off by default. Document consent and collection policy before explicitly enabling it.
7. Process termination is available only to administrators; the button is disabled without creation-time metadata. Confirm the target and inspect the resulting command status. A queued command is not proof of execution.
8. Configure Telegram or SMS credentials through settings. Twilio also requires Account SID and sender number. Test buttons use dedicated test routes. No live recipient delivery was performed in development.

The bundled OS setup scripts are convenience tools, not signed enterprise installers. Validate installation, ACLs, Python dependencies and uninstall behaviour on each target OS. Do not claim macOS/Windows certification from Linux tests. See installer output for whether it runs at login or as a service. Removing auto-start configuration does not necessarily terminate an already running Windows process.

Updated installer usage (from the extracted release with dependencies installed):

```
python install_agent.py --device LAPTOP-01 --server https://your-server.example
python install_agent.py --uninstall
```

Tokens are read from an environment variable or hidden prompt. Enrollment is JSON, never executable shell configuration. Installation copies the local release and does not download an unpinned agent. macOS uses a per-user LaunchAgent; Windows uses a per-user Startup entry (login-triggered, not a Windows service). Native-platform behaviour remains unverified.
