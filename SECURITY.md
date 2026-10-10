# Security Policy

`nih-sftp-server` parses untrusted input directly from a network-facing SSH
session with no sandboxing of its own (see the README's "What this is *not*"
section) - treat any parsing, buffer-handling, or filesystem-path bug as a
potential security issue.

## Reporting a vulnerability

If you find a security issue, please open an issue - or, for anything you'd
rather not post publicly first, [contact the maintainer
directly](https://eddylangley.net/contact/).

## Supported versions

This project has no long-term-support branches; security fixes are made
against the latest release. See [Releases](https://github.com/eddylangley/nih-sftp-server/releases)
for what's current.
