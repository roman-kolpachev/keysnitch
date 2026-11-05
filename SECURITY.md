# Security policy

keysnitch is a security tool, so its own bugs can matter. Thank you for reporting them.

## How to report

Please do **not** open a public issue for a vulnerability.

Use GitHub's private reporting instead: open the **Security** tab of this repository and click **Report a vulnerability**. You will get an answer within 3 working days.

Please include a short example that shows the problem. Never send a real, live credential. A fake value with the right shape is enough.

## What counts as a vulnerability

- A pattern that can be made slow on purpose (ReDoS), so a scan takes much longer than linear time.
- A finding that leaves part of a credential readable (the reported range is too short).
- A matched value that leaks into an error message, a thrown exception or any other output that is not the finding itself.
- A crash or a hang on any input.

## What is not a vulnerability

- A credential format that keysnitch does not know yet. Please open a normal issue with the "New key format" template. It is welcome.
- A false positive. Please use the "False positive" issue template.

## Supported versions

Until 1.0, only the latest minor version gets security fixes.
