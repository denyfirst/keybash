# 0011 — Files: moving files to and from a server in the browser

Date: 2026-11-27. Status: accepted. The maintainer asked for it on the same
day: a Files page that is good to look at and easy to use, with security
still first. Its look waits for their go-ahead before the server side is
built. It keeps every rule of ADR 0005, ADR 0009 and ADR 0010.

## Context

People reach a server's shell through Keybash without ever seeing the
account's key or password. To move a file there or back, today they need
their own SFTP client, and so the account's secret. That is the one thing
ADR 0010 took away.

A person with a terminal can already move a file through it, for example by
pasting text or by fetching from the server. So Files adds comfort, not a new
power. It still deserves its own switch: a person who may type commands is
not always one who should carry files out.

What we have to build on:
- **The worker.** The sandboxed worker (`SSH-PROCESS-LAB.md`) already holds
  the one SSH connection, after the host key matched its pin. It has no
  sockets, no programs and no writable files of its own. Its frames are at
  most 32 KiB.
- **Admission.** The gateway already does everything a session needs: the
  ready sign-in, the account grant, the one-use lease, the quotas, idle and
  sign-out endings, and revocation when an account or server changes.
- **Server keys.** The key line Keybash writes on a server, `restrict,pty`,
  does not block the `sftp` subsystem, so key accounts work as they are.
- **No record yet.** There is no audit record yet (PRODUCT-PLAN, "Audit").

## Decision

### What a person sees

- **On the Access page**, a server that allows files gets a **Files** button
  next to **Connect**. It opens `/remote/files/{account}` in a new tab.
- **The Files page** follows the person's light or dark choice, like the
  workspace. The terminal and the desktop stay dark.
- It shows one folder at a time, opening in the account's home folder. A row
  gives the name, size and change time.
- **Path bar.** Each part of the path is a step back. Typing a path goes
  straight there.
- **Actions.** Upload (the button, or dropping files on the page), New
  folder, Rename, Delete and Download, on the row and on a selection.
- **Transfers tray.** It shows each transfer's progress, speed and a Cancel.
- **Keyboard.** Enter opens a folder, Backspace goes up, F2 renames, Delete
  deletes. The page never needs a mouse.
- **Download only.** When the server is set to it, the page shows only
  Download and opening folders, and says why.
- **An upload never leaves half a file.** It goes to a hidden name in the
  same folder and is renamed into place once complete; a replaced file is
  removed only then. A cancelled or failed upload removes its hidden file.

### The administrator's switch

- Each SSH server gets **File transfer** under "This server":
  - **Off.** This is the default, and every existing server reads as Off.
  - **Download only.** Folders can be listed, and files downloaded.
  - **Upload and download.** It adds upload, new folder, rename and delete.
- It is stored on the server record as `Files` (`""`, `"download"` or
  `"both"`), with `omitempty`, so records that never set it keep their old
  form.
- Changing it is like every server change: administrator, fresh proof (step-up
  within ten minutes), the rate limit. It is checked again inside the write
  transaction.
- A change ends that server's open Files sessions; its terminals stay. A
  Files lease keeps the mode it was granted with, and is refused at redeem
  when the server no longer allows that mode.
- RDP servers do not get the switch. Desktop file transfer stays refused
  (`rdpdr`), as before.

### One Files session, its own kind

- A Files session is admitted exactly like a terminal. It counts against the
  same per-person and total limits, and the same sign-out, idle and revocation
  endings end it.
- The lease carries its kind (`terminal` or `files`), and is redeemed only on
  its own socket. A Files lease is issued only while the server allows files,
  and that is checked again at redeem.
- The worker's start frame gains `Kind` and the allowed mode. A Files worker
  authenticates exactly as today, then opens one session channel and asks for
  the `sftp` subsystem. It asks for no PTY, no shell and no exec. It refuses
  every terminal frame, and a terminal worker refuses every file frame.
- The worker enforces the mode a second time. A Download-only worker refuses
  every write, whatever the gateway sends.

### A small SFTP client of Keybash's own

- It lives in the worker. It speaks SFTP version 3, the version OpenSSH
  serves, with only these requests:
  - `REALPATH`, `OPENDIR`, `READDIR`, `CLOSE`, `LSTAT` and `STAT`;
  - `OPEN`: for reading a regular file (checked with `STAT` first, since
    opening a FIFO can hold the server), or for a new file, always
    `CREAT|EXCL`. A replace the person confirmed uploads to a fresh hidden
    name like any upload; the old file is removed only once the new one is
    complete, and the new one renamed into its place;
  - `READ` and `WRITE`;
  - `MKDIR`, `RMDIR`, `REMOVE` and `RENAME`. Version 3's rename never replaces
    an existing name.
- Nothing else is sent: no attribute changes, links or extensions.
- An outside library would bring a large client and server. Fewer than a
  thousand lines here are easier to bound and fuzz.
- **Bounds.**
  - A server packet is at most 256 KiB, checked before it is read.
  - A name is at most 255 bytes, and a path at most 4096.
  - A folder lists at most 10,000 entries.
  - At most 8 reads or 8 writes of 32 KiB are in flight.
  - A reply to an unknown request ends the session.
- The gateway never sends SFTP packets. It sends one of a fixed set of
  operations, and the worker builds the packets.

### The frames, browser to server

- **Browser to gateway.** The Files socket is the terminal's:
  - the first message carries the CSRF token and the lease;
  - requests are strict JSON of at most 16 KiB, one operation at a time;
  - file bytes are binary frames of at most 32 KiB, with the terminal's
    window of 32 unacknowledged frames.
  - Failures are fixed words: `exists`, `missing`, `denied`, `not-empty`,
    `too-large`, `not-allowed`, `failed`.
- **Gateway to worker.** New frame kinds for a request, a batch of entries,
  data, done, failed and cancel. Each has its limit checked before
  allocation, like today's frames.
- **No disk.** Files never touch the Keybash server's disk. The worker's root
  is read-only and its file-size limit is zero. The gateway holds only the
  frames in flight.

### Remote names are untrusted

- The page writes every name as text, never as markup.
- Control and direction characters are shown as visible marks. Otherwise a
  name like `invoice`, U+202E, `txt.exe` would display as `invoiceexe.txt`.
- A name that is not UTF-8 is listed as unreadable, and offers no action.
- A path the page sends must be absolute UTF-8 without NUL, at most 4096
  bytes. The gateway checks it again. The account's own rights on the server
  decide the rest. Keybash adds no folder limit of its own.
- Every download is saved as `application/octet-stream` under a name with its
  control characters replaced. The page never opens, previews or runs a file.

### Sizes

- A file is at most 2 GiB each way.
- The page streams uploads from the disk. It collects a download in memory and
  saves it when complete.
- The Files page's security headers are the terminal page's.

## Phases

1. This record, and the page against a preview backend, for the maintainer's
   look.
2. The worker's Files kind and SFTP client, with its fuzz target and a real
   `sftp-server` in the Linux tests.
3. The switch, the lease kind, the socket, the Access page button and the
   Files page, with browser tests.
4. A live check on the test VM against OpenSSH on Ubuntu and on Windows
   Server.

## Tests

Following `ENGINEERING.md`, with sabotage both ways:
- refusal:
  - for Files on a server set to Off, on RDP, and after the switch is turned
    off between grant and redeem;
  - for a terminal lease on the Files socket, and the other way round;
  - for every write on a Download-only server, at the gateway and again in
    the worker;
- the worker never asking for a PTY, a shell or an exec in a Files session;
- every frame, packet, name, path, listing and size limit, malformed and
  oversized, with a fuzz target on the SFTP reply decoder;
- `CREAT|EXCL` unless replacing was confirmed, and rename never replacing;
- names with control and direction characters shown visibly, never as markup;
- fresh proof for the switch, and sessions ending when it changes;
- nothing written on the Keybash server's disk.

## Limits

- **The record.** ADR 0012 writes each operation that moves or changes a
  file, with its person, server, account, path, size and outcome. Opening a
  folder is not recorded.
- **The server decides the rest.** Keybash does not inspect what is moved.
  The account's rights on the server decide what can be read or written.
- **Large downloads use the browser's memory**, up to the 2 GiB limit.
- **One operation at a time.** While a file moves, opening another folder
  waits for it; a folder goes ahead of transfers still waiting.
- **CPU.** The worker's limit on CPU time also ends a Files session. The page
  then offers to connect again.
- **Windows** servers need OpenSSH with its SFTP subsystem, which Windows
  Server ships but does not start by default.
