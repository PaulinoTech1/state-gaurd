# First usable State Guard prototype
Goal: make this placeholder accessible through a CLI and desktop interface.
User scope: "A graphical interface alongside the CLI".
Constraints: Python standard library; Windows/Linux; no automatic system changes.
Inputs: native endpoint settings or explicit JSON desired-state policy/config.
Outputs: readable/JSON reports, preview, guarded JSON remediation and recovery copy.
Done when: CLI audit/preview work; drift and write failure tests pass; GUI provided;
platform limitations documented. Desktop interaction and Linux native checks remain
unverified in the local Windows environment.
Approaches: documentation alone lacks a usable tool; a web app adds server/dependency
maintenance; Python CLI plus Tkinter is the smallest desktop-capable implementation.
AgentDB executable was unavailable; repository contained only a placeholder README.
