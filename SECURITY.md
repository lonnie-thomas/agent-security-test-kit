# Security policy

## Scope

This repository is a **test kit** with a deliberately vulnerable toy agent and synthetic data. It is not deployed anywhere and holds no real credentials. The toy agent is intentionally unsafe, so its failures are **not** vulnerabilities; please do not report them.

Worth reporting: a flaw in the kit itself, for example a test that passes when the agent is actually vulnerable (a false pass), a detector that is trivially "always pass", an adapter that leaks or mishandles data, or code in the kit that could be abused when pointed at a real system.

## How to report

* **Preferred:** use GitHub's private vulnerability reporting. On the repository page choose **Security**, then **Report a vulnerability**, and include the steps to reproduce.
* If that option is not available, open a GitHub issue titled "Security contact request" **without** exploit details, and the maintainer will arrange a private channel.

Please include: the affected file or test ID, what you expected versus what happened, minimal reproduction steps, and the commit you tested.

## What to expect

This is a personal project maintained on a best-effort basis. I aim to acknowledge reports within about a week and to fix or document confirmed issues, crediting reporters who want credit. There is no bug bounty and no service-level agreement.

## Responsible use

Only run this kit against agents and systems you own or are explicitly authorised to test. Never post real secrets, tokens, or personal data in an issue or report.
