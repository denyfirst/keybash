# Keybash — local interactive UI demo

The demo lets you try the interface yourself and report what is missing. It is
not an installed product and makes no real server connection. It does not
touch Porch or Rootwell, and uses only the development tools in the Keybash
repository.

## Opening it

In Windows PowerShell, in the root of the Keybash repository:

```powershell
./scripts/demo.ps1
```

You need:
- the Go version named in `go.mod`;
- Node;
- the development dependencies for `web/`, installed from the lockfile.

The script opens the installed Edge in a separate, temporary browser context.
It changes neither the normal Edge profile, nor the operating system's TLS
trust, nor any other project's configuration, and installs no browser. On
another development system, first install the pinned pnpm frozen-lockfile
dependencies for `web/` and Playwright Chromium as `ENGINEERING.md` describes.

### Without Node (Go only)

```powershell
./scripts/demo.ps1 -Serve
```

The same synthetic demo account, keys and two sample connections are prepared
in Go and served at `https://127.0.0.1:8443/login`. The terminal prints:
- the username and the password;
- the MFA seed;
- the one-time recovery codes.

To sign in, use the password with either a code from your authenticator or one
of the recovery codes; each recovery code works once.

The certificate is made anew on every start, and no browser knows it. In Edge,
choose **Advanced → Continue to 127.0.0.1** to accept the warning for this
address only. The operating system's TLS trust is not changed. Never do this
for real servers. The demo stops with Ctrl+C, or after one hour.

The demo opens a guide page and the workspace. The guide has an **Open the
workspace** button, the demo username and password, the current MFA code and
the remaining one-time recovery codes. Every start makes a new temporary
instance and new test keys. The first sign-in and MFA are completed through
the normal UI automatically. There is no MFA, CSRF or ownership bypass.

An MFA code cannot be used twice. Wait for the code used at start to expire,
or use one of the unused recovery codes on the guide page.
- Adding keys and connections, and connecting, need no code.
- Showing and deleting do, if more than 10 minutes have passed since sign-in:
  a small window asks for the phone's code (or a recovery code) and then
  carries on.
- If you change the password or the MFA, the guide's details may no longer
  match. Restarting the demo returns it to a clean state.

## What to try

- **Account:** sign-in, MFA, sign-out, re-verification, the encrypted record
  list, and adding, showing and deleting synthetic records.
- **Connections:** **Connect** on the two samples, creating a new connection,
  the selectors, naming, and moving between windows.
- **Terminal:** `help`, `whoami`, `hostname`, `pwd`, `ls`, `uname`, `date`,
  `echo hello`, `clear` and `exit`. Also try:
  - Unicode text;
  - selecting and copying;
  - the paste review;
  - Ctrl+C and Ctrl+L;
  - how the terminal looks when resized.
- **Desktop:** a test picture marked SIMULATION; clicks and typing change it.
  Backspace, Enter, local full screen and the **Disconnect** button.
- **Revocation:** open both connections, then choose **Sign out** in the menu.
  Both views must close and the picture must be cleared.

The terminal is a list of synthetic commands, not a Linux shell. There is no
vim, tmux, real filesystem, process or job control, shell quoting or real SSH
protocol here. The desktop is not Windows, and this preview starts no native
RDP or NLA server. The separate SSH and native RDP CI tests are the protocol
evidence; this demo does not replace them. Metadata and page titles show that
it is a simulation; nothing leads to a real server or a local shell.

**Enter only made-up test data.** The demo is not built to accept real
credentials.
- In the test browser context, HTTP requests are filtered to that random
  loopback HTTPS origin. This is not a claim of a general host or browser
  egress sandbox.
- The fixture certificate is accepted only in that separate test browser
  context.
- No demo exception was added to the production target guard, the pins or
  Linux storage admission.
- The portable storage and worker seams live only in `browserlab` test files
  and are not part of the product binary.

Closing every demo browser window, or Ctrl+C in the script, stops it. There is
also a one-hour maximum.
- On a normal exit, the test database is removed from the temporary
  directory. If the process or the computer is stopped by force, only
  synthetic encrypted test remains can be left in the OS temp directory.
- The instance encryption key and the synthetic private key live only in
  process memory; the demo does not survive a restart.
- Forensic erasure of the browser profile is not claimed.
- The current limit of two active or pending connections applies. There is no
  lifetime output limit; heavy output slows the stream rather than closing it.

## Automatic check and feedback

```powershell
./scripts/demo.ps1 -Check
```

The headless Edge check covers:
- the guide;
- the normal bootstrap, MFA and re-verification flow;
- the two owned samples and the terminal's answer;
- an actual pixel change on the desktop from the keyboard and mouse;
- revocation at sign-out.

Linux CI runs the same check with Chromium and the race detector. The
test-only parser refuses malformed, clipboard and out-of-bounds input. The
existing transport, identity and native security gates stay in place.

For feedback, say which screen, which step and what you expected, for example:
"Desktop → full screen → Esc: the size stayed like this; I wanted it to…".
Never put credentials or recovery codes in feedback text or screenshots.
