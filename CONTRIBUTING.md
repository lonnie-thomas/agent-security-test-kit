# Contributing

Thanks for your interest in the Agent Security Test Kit. This is a small portfolio and reference project, so contributions are kept simple.

## Ground rules

* **Synthetic data only.** Never add real names, hosts, tickets, keys, or tokens. Use `example.test` addresses and obviously fake secrets.
* **Keep it deterministic and offline.** Tests must not call a network service or a live model, and results must be repeatable.
* **Test outcomes, not wording.** Assertions should check the executor's ledger, system state, or audit log, not the model's text. That is what keeps the kit model-agnostic.
* **Every new test needs a reason to fail.** Add or extend a positive control, and show the test fails against the toy agent or a mutated agent, otherwise it proves nothing.
* **Be honest in the docs.** Do not claim certification, compliance, or live-model results the repository does not demonstrate.

## Set up and test

```bash
git clone https://github.com/lonnie-thomas/it-service-agent-demo.git
git clone https://github.com/lonnie-thomas/agent-security-test-kit.git
cd agent-security-test-kit
python3 -m venv .venv && . .venv/bin/activate
pip install -e . -e ../it-service-agent-demo
python -m pytest                              # the kit's self-checks
agent-sec-kit run --agent it-service-agent    # expect all scored tests to pass
agent-sec-kit run --agent toy                 # expect failures, on purpose
```

## Good first contributions

* A new hidden-instruction carrier in `src/agent_security_kit/payloads.py`.
* A new adapter for another human-gated agent (see the adapter table in the README).
* A new test in `src/agent_security_kit/suite/` with severity and OWASP (Open Worldwide Application Security Project) metadata.

## Pull requests

1. Open an issue first for anything larger than a small fix.
2. Create a branch, make a focused change, and add or update tests.
3. Run the commands above and confirm the results match the README (30 of 30 scored tests pass on the reference agent; the toy agent still fails the expected tests). If results change, regenerate the files in `reports/` and update the README tables.
4. Write a clear commit message (for example `feat(suite): add replay-after-restart test`) and describe what changed and why.

By contributing, you agree that your contribution is licensed under the MIT license in [LICENSE](LICENSE).

For security problems, please do not open a public issue; see [SECURITY.md](SECURITY.md).
