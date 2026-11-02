# Security boundaries

Sentinel is an endpoint monitoring and investigation prototype, not a certified EDR/DLP/compliance product.

- Device and user authentication are separate. User access requires a login-issued session and server-enforced role. MFA is enforced for enrolled accounts; raw admin passwords/tokens are not API bearer credentials.
- MFA enrollment revokes that user's existing sessions. Repeated successful use of the same login TOTP step is rejected. MFA seeds remain database secrets, not hardware-bound credentials.
- Self-reported agent hashes are change indicators, not trusted attestation. A compromised endpoint can lie about its telemetry. Watchdog restarting is availability support, not tamper resistance. PyInstaller packaging is not obfuscation.
- Process termination requires name and creation time. If a supplied executable path cannot be verified, execution is refused. PID reuse and protected-process checks reduce risk; OS-specific validation is still required. This is operator-directed response, not automated malware removal.
- Commands carry expiry, are retried until expiry, and require endpoint acknowledgements. Persistent journals record intent before action. After a crash in the action window, the agent reports an unknown outcome as failed and does not repeat it. This favors avoiding repeated actions over guaranteeing execution. Exactly-once execution is not claimed. Corrupt/unwritable journals stop remote actions.
- Notification subprocess completion does not prove a human saw a popup. Remote notification-provider acceptance does not prove SMS/Telegram recipient delivery.
- Queue protection uses filesystem permissions, not application-level encryption.
- The heuristic score is an informal alert-based indicator, not certified compliance or probability of compromise. Higher legacy score values indicate fewer alert penalties.
