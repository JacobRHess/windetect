# Security policy

windetect is a personal detection-engineering lab with no hosted deployment to attack. If you
find a security issue in this code, though (for example a way the capture slicer could run
attacker-controlled input, or a CI workflow that could leak a token), please report it
privately rather than opening a public issue.

## Reporting

Use GitHub's private vulnerability reporting (the **Report a vulnerability** button under the
Security tab) or email hess.jacobr@gmail.com. I aim to respond within a few days.

## Design notes

- Capture exports are treated as untrusted input. The EVTX XML is parsed with `defusedxml`
  (never the stdlib parser), sliced events are schema-validated before they land as
  fixtures, and fixture paths are contained within the repository.
- Subprocess calls pass argument lists with no shell.
- TLS verification to Splunk is off by default for the lab's self-signed localhost cert and
  is turned on with `WD_SPLUNK_VERIFY=true` for a real, trusted endpoint.
- Credentials in this repo (the HEC token, the dev Splunk password) configure an ephemeral
  local or CI Splunk only. They are not secrets.

## How this repo is checked

- Third-party GitHub Actions are pinned to commit SHAs; checkouts set
  `persist-credentials: false`; workflow permissions are read-only.
- The Splunk image that runs in CI is pinned by digest.
- Dependencies are locked (`uv.lock`) and scanned with `pip-audit`; Dependabot proposes
  updates weekly.
- The source is scanned with `bandit` (no blanket skips).
- The workflows are audited with `zizmor` (online checks enabled) and the git history with
  `gitleaks`.
- Every push replays the committed detections against a real Splunk and gates on the result.
