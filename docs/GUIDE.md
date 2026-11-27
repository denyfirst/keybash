# Using Keybash

What each page is for, and what its words mean. The pages themselves say
only what you need to act; the reasons are here. Installing, the networks
servers may be in, and the commands for each server are in `INSTALL.md`.

- [Your servers](#your-servers)
- [Servers](#servers)
- [A server's page](#a-servers-page)
- [People](#people)
- [Installation](#installation)
- [Account](#account)
- [How Keybash looks](#how-keybash-looks)

## Your servers

One card for each server account you are on. **Connect** opens it in its own
tab, and Keybash signs you in as that account. You never see its key or
password.

Who signs in with an account, administrators included, is chosen on its
server's page under **Servers**. An administrator sees a server here only
after putting themselves on one of its accounts.

A card's state:
- **Ready:** it opens.
- **Server changed:** the server shows a different certificate, so Keybash
  will not connect and sends it no password. Your administrator has to check
  it.
- **Unavailable:** it is outside the networks Keybash may reach, or its
  certificate has ended.
- **Not checked:** your administrator added this desktop without comparing it
  on its own screen.

## Servers

Administrators add servers here; auditors read the page.

A server is reachable only inside the networks set on the Keybash server
(`--target-networks`, set at install or with `upgrade.sh`; see `INSTALL.md`).
Nobody reaches it, administrators included, until it has an account with
people on it, and each person signs in only as the accounts they are on.

Its identity (an SSH host key or an RDP certificate) is pinned when it is
added. If it changes, Keybash refuses the server until an administrator
compares the new one on the server's own screen and accepts it.

**Adding a server.** Choose Terminal (SSH) or Desktop (RDP), a name and, with
the picture at the start of the name field, the picture on its cards (a
desktop starts as Windows), then its IP address and port. The address must be
inside the networks this Keybash may reach; if it is not, Keybash says so and
names them. Keybash reads the server's identity, and you compare it on the
server's own console before it is added; `INSTALL.md` has the commands. Next
you add the account people sign in as.

A server's state:
- **Ready:** people on its accounts can connect.
- **Identity changed:** it shows a different host key or certificate, usually
  because Windows renewed its own. Nobody can connect until you check it.
- **Certificate ended:** nobody can connect until you check the certificate
  the server shows now.
- **Ending soon:** Windows renews it by itself; Keybash then asks you to check
  the new one.
- **Not checked:** it was added without comparing it on the server's own
  screen, so Keybash cannot be sure it is your server. **Check identity**
  compares it now.
- **Not reachable:** it is outside the networks this Keybash may reach, or its
  identity cannot be used.

## A server's page

**Server identity** is what Keybash compares each time it connects: it
connects only while the server shows this identity.

**Accounts.** An account is one way in: its name on the server, and a key or
password that Keybash keeps. People sign in only as the accounts they are on,
and never see the key or password. A server may have up to 16 accounts.

- **Key kept by Keybash (safer):** Keybash makes the key, and nobody ever sees
  it. Put its line on the server once, with the command the page gives you,
  run as that account. Your own key, or the console, is only how you put the
  line there: Keybash never takes a key of your own, because copies of it
  live elsewhere and anyone holding one could sign in without Keybash.
  - **Not set up yet:** the key has not opened a session.
  - **Set up:** it has.
  - **New key waiting:** a replacement waits beside the current key until you
    put its line on the server and switch to it.
- **Password kept by Keybash:** the account's own password, typed once. Anyone
  who already knows it can still sign in without Keybash, so change it when
  one of them leaves: on the server first, then here.

**Change who** chooses the people who sign in as an account. Taking someone
off, or removing the account, ends their open sessions through it at once.

**This server**
- **Name:** everyone who signs in to it sees it.
- **What runs on it:** only the picture on its cards. Keybash connects the
  same way whatever it is.
- **Remove server:** open sessions to it end at once, and its accounts go with
  it: their keys are destroyed and their passwords forgotten.

## People

Each person signs in to Keybash with their own password and the authenticator
on their phone. Nobody else ever sees either. They reach servers only through
the accounts an administrator puts them on, and never see those accounts'
keys or passwords.

Roles:
- **User:** connects to the servers an administrator puts them on.
- **Auditor:** sees the servers and who may use them. Reaches no server.
- **Administrator:** manages servers and people, and connects where they put
  themselves.

A change to a person (role, block, reset, delete, or the servers they sign in
to) ends their open sessions at once. Inviting someone and resetting access
are described in `INSTALL.md`, under "Adding people".

## Installation

What this copy runs, and how to update it.

- **Server keys and passwords** are encrypted on this server under its own
  key. Nobody is ever shown them: they leave only to sign people in.
- **Sent to us:** nothing. This copy reports to no one and never checks for
  updates by itself.

Updating stops Keybash for a moment, so open sessions close. Settings, people,
servers and their accounts stay. The previous version is copied to
`/var/backups/keybash` first and put back by itself if the new one does not
start. Until Keybash publishes signed releases, an update trusts the code
GitHub serves over HTTPS. `INSTALL.md` has the steps, under "Upgrading".

## Account

- **Password:** the one you sign in to Keybash with. Changing it closes all
  your open sessions.
- **Authenticator:** the 6-digit code on your phone. Replace it when you
  change phones: the old one keeps working until the new one is confirmed.
  When Keybash asks for the code, type it at once: it goes by itself as the
  sixth digit arrives. **Use a recovery code** under the boxes takes one of
  those instead.
- **Recovery codes:** one-time codes for signing in when your phone is lost.
  Making new ones stops the old ones at once.

## How Keybash looks

The sun or moon button switches between light and dark. The choice is kept
with your account on the Keybash server and reaches every page: the
workspace, the terminal and desktop pages, and the sign-in page, which takes
it from a copy the server leaves in your browser.

The button at the end of the menu's **Workspace** caption folds the menu to
its icons, and opens it again. That choice is kept with your account too.
