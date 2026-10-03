> **This is a fork of [rustdesk/rustdesk](https://github.com/rustdesk/rustdesk)**, the open-source
> RustDesk remote desktop client (AGPL-3.0). Full credit for the base client goes to the RustDesk
> team and its contributors.
>
> This fork ("RDC") adds a managed-fleet layer on top of the stock client, designed to pair with
> [rustdesk-managed-directory-api](https://github.com/MAGA-Brad/rustdesk-managed-directory-api)
> ("RDS"), a self-hosted Client directory and management server, and
> [rustdrop-storage](https://github.com/MAGA-Brad/rustdrop-storage) ("RD"), the storage service
> behind RustDrop file drops. Together they turn RustDesk from a remote-desktop tool you configure
> one machine at a time into a fleet you actually manage: Clients enroll themselves, a Client
> Manager approves them from a web UI, and signed updates roll out to everyone automatically —
> verified before they install, and never in the middle of a remote session. It also depends on a sanitized fork
> of [rustdesk/hbb_common](https://github.com/MAGA-Brad/hbb_common) as a submodule.

## What this fork adds

### Managed enrollment, not manual configuration
- A Client enrolls itself at install time — no per-machine server/relay/key configuration for end
  users to get wrong. The install form collects a friendly Client name, a contact email and an
  optional local access password (which requires 2FA), authenticates against a shared enrollment
  password, and the Client shows up in the directory as **pending**. Until a Client Manager approves
  it, it holds no directory credential — no fleet directory, relay-access lease, chat, RustDrop or
  updates.
- If a Client is blocked or denied, or its key changes while it's still pending, it isn't
  permanently orphaned — an **Owner-authorized re-enrollment** flow returns it to pending under its
  original directory record, revoking every old credential and relay lease before a replacement can
  be issued on re-approval. (Revoked is terminal.)
- Network settings are hidden from end users: no Server/Proxy/WebSocket fields to misconfigure,
  any WebSocket link is pinned to `wss://`, and all directory traffic is HTTPS-only to the one
  server compiled into the build.

### Signed, gated auto-updates
- Release manifests are Ed25519-signed on RDS at publish time. The client checks the signature against a public key
  compiled into the build, then checks the downloaded installer's size and SHA-256 against the
  signed manifest — a compromised or malicious update server can't push arbitrary code to a fleet.
- Updates install automatically, with no prompt. The client's background service checks for a
  newer signed build 30 seconds after it starts and every 30 minutes after that, and installs it as
  soon as it's verified. The one gate: it never installs while a remote session is active — it
  waits and tries again in 30 minutes.
- While a verified update is waiting, the client shows **"Update Available"**, and **Update Now**
  applies it immediately (same no-active-session rule).
- The install is launched by the managed client's own background service, so no UAC prompt is
  needed on the end user's machine — and only an installer that passed the signature and hash
  checks above is ever launched that way.
- One installer for every Windows PC: it carries both the x64 and the ARM64 build and installs
  the one native to the machine it runs on. RDS publishes a signed manifest per architecture.

### Built for a real fleet, not a demo
- Multi-process aware: the GUI, the background Windows service, and the per-session connection
  process each run independently — enrollment status, pending-update state, and update triggers
  are relayed between them over an authenticated local IPC channel rather than assumed to be
  shared state.
- CGNAT-friendly: RDS's relay guard leaves the registration and relay-data ports to RustDesk's own
  protocol-level authentication rather than the relay-lease source-IP allowlist, because carrier NAT
  pools (a mobile hotspot, for example) can give the lease call and the registration socket
  different public IPs.
- A local-input-priority guard (Windows): the moment the person at the machine moves the mouse,
  remote mouse and keyboard input is dropped for a short window (1–5 s, adjustable) — and remote
  block-input/privacy mode are disabled, so nobody connected remotely can lock the local user out.
- Windows installer/service hardening and protected credential storage: the enrollment credential
  is DPAPI-encrypted in a file whose protected ACL admits only SYSTEM and Administrators — not
  sitting in a plaintext config file.

### Locked down by default
- Password and unattended access always require TOTP 2FA on a managed Client.
- Camera, terminal and tunneling sessions are refused; audio, remote printer, session recording,
  block-input and privacy mode are forced off; trusted devices, LAN discovery and the third-party
  notification bot are disabled.
- A SYSTEM-level watchdog keeps the client's service running, and end users can't stop it from the
  UI.
- Session start and end are reported to RDS, which drives the dashboard's "In session" and
  "Connected To" views.

### Pairs with RDS and RD
This client is one part of a set of three:
- **RDS** — enrollment API, Client Manager accounts with 2FA, audit logging, relay-access leasing,
  signed update manifests, and the admin UI — lives in
  [rustdesk-managed-directory-api](https://github.com/MAGA-Brad/rustdesk-managed-directory-api). It
  runs alongside a stock hbbs/hbbr and gates it at the firewall rather than proxying it, so this
  isn't a fork of the relay/rendezvous protocol at all — just real fleet management layered on top
  of it.
- **RD** — [rustdrop-storage](https://github.com/MAGA-Brad/rustdrop-storage), the blob store that
  holds RustDrop's encrypted files. Clients never talk to it directly: RDS authorizes every
  transfer and streams the ciphertext to and from it.

### Managed chat
- A lightweight text channel to a specific managed Client, separate from RustDesk's own in-session
  chat — works whether or not a remote-control session is active, relayed through RDS rather than
  the relay/rendezvous server. Messages wait on RDS (up to 30 days) for a Client that's offline.
  Useful for a quick "starting your remote session now" without a separate side channel.

### RustDrop — managed, end-to-end encrypted file drops
> **In active development.** Treat as experimental — not yet feature-flagged off, and some rough
> edges are still being worked through.
- An end-to-end encrypted way to send a file between two managed Clients, resumable across
  network drops and pauses, replacing the legacy file-transfer buttons in the managed client UI.
  Transfers go through RDS, which stores the
  ciphertext on RD (rustdrop-storage), rather than through the relay/rendezvous server — so no
  remote-control session needs to be active on either end.
- RustDrop is a window of the client itself. There's no signaling between the two machines
  directly; RDS brokers the handoff and neither side ever gets raw file-system access to the other.
  When a file arrives, the RustDrop window opens (or comes to the front) in the signed-in user's
  session on the receiving machine.
- Content is encrypted client-side (X25519 + XChaCha20-Poly1305) with a keypair each Client
  generates locally — only the public half is registered with RDS. RDS relays ciphertext and never
  holds a private key (it does see file names and sizes, and is trusted to hand out the right
  public keys).

### Support and diagnostics, built in
- An **About** screen shows the build number, build date, RustDesk ID and key fingerprint — the ID
  and build number are what a Client Manager sees for that Client in RDS, so matching a support call
  to a dashboard entry doesn't require guesswork.
- **Remote debug-log requests**: the primary Owner account can request a Client's debug log from
  RDS — one Client or every approved Client at once — delivered on its next check-in, without
  needing a remote session into the machine first just to go looking for logs. Clients also upload their new log lines hourly on their own
  (only what's new since the last upload), catching up as soon as they're back online.
- The client self-reports its managed build number on every heartbeat, so RDS's Client Management
  view always shows real per-Client build/update status instead of an assumed one.

## Screenshots

| | |
|---|---|
| ![Managed Client directory](screenshots/RDC_Directory.png) | ![RustDrop — send to a managed Client](screenshots/RustDrop_Directory.png) |
| ![RustDesk and RustDrop side by side, light theme](screenshots/RDC_RustDrop_Light.png) | ![RustDrop — incoming and outgoing transfers](screenshots/RustDrop_Pending_Transfer.png) |
| ![RDS admin dashboard — Group Management overview](screenshots/RDS_Dashboard_Overview.png) | ![RDS admin dashboard — Client build/update status](screenshots/RDS_Client_Update_Status.png) |
| ![RDS admin dashboard — Server Health](screenshots/RDS_ServerHealth.png) | |

---

Everything below this notice is the upstream RustDesk project's own README, unmodified.

---

<p align="center">
  <img src="res/logo-header.svg" alt="RustDesk - Your remote desktop"><br>
  <a href="#raw-steps-to-build">Build</a> •
  <a href="#how-to-build-with-docker">Docker</a> •
  <a href="#file-structure">Structure</a> •
  <a href="#snapshot">Snapshot</a><br>
  [<a href="docs/README-UA.md">Українська</a>] | [<a href="docs/README-CS.md">česky</a>] | [<a href="docs/README-ZH.md">中文</a>] | [<a href="docs/README-HU.md">Magyar</a>] | [<a href="docs/README-ES.md">Español</a>] | [<a href="docs/README-FA.md">فارسی</a>] | [<a href="docs/README-FR.md">Français</a>] | [<a href="docs/README-DE.md">Deutsch</a>] | [<a href="docs/README-PL.md">Polski</a>] | [<a href="docs/README-ID.md">Indonesian</a>] | [<a href="docs/README-FI.md">Suomi</a>] | [<a href="docs/README-ML.md">മലയാളം</a>] | [<a href="docs/README-JP.md">日本語</a>] | [<a href="docs/README-NL.md">Nederlands</a>] | [<a href="docs/README-IT.md">Italiano</a>] | [<a href="docs/README-RU.md">Русский</a>] | [<a href="docs/README-PTBR.md">Português (Brasil)</a>] | [<a href="docs/README-EO.md">Esperanto</a>] | [<a href="docs/README-KR.md">한국어</a>] | [<a href="docs/README-AR.md">العربي</a>] | [<a href="docs/README-VN.md">Tiếng Việt</a>] | [<a href="docs/README-DA.md">Dansk</a>] | [<a href="docs/README-GR.md">Ελληνικά</a>] | [<a href="docs/README-TR.md">Türkçe</a>] | [<a href="docs/README-NO.md">Norsk</a>] | [<a href="docs/README-RO.md">Română</a>]<br>
  <b>We need your help to translate this README, <a href="https://github.com/rustdesk/rustdesk/tree/master/src/lang">RustDesk UI</a> and <a href="https://github.com/rustdesk/doc.rustdesk.com">RustDesk Doc</a> to your native language</b>
</p>

> [!Caution]
> **Misuse Disclaimer:** <br>
> The developers of RustDesk do not condone or support any unethical or illegal use of this software. Misuse, such as unauthorized access, control or invasion of privacy, is strictly against our guidelines. The authors are not responsible for any misuse of the application.


Chat with us: [Discord](https://discord.gg/nDceKgxnkV) | [Twitter](https://twitter.com/rustdesk) | [Reddit](https://www.reddit.com/r/rustdesk) | [YouTube](https://www.youtube.com/@rustdesk)

[![RustDesk Server Pro](https://img.shields.io/badge/RustDesk%20Server%20Pro-Advanced%20Features-blue)](https://rustdesk.com/pricing.html)

Yet another remote desktop solution, written in Rust. Works out of the box with no configuration required. You have full control of your data, with no concerns about security. You can use our rendezvous/relay server, [set up your own](https://rustdesk.com/server), or [write your own rendezvous/relay server](https://github.com/rustdesk/rustdesk-server-demo).

![image](https://user-images.githubusercontent.com/71636191/171661982-430285f0-2e12-4b1d-9957-4a58e375304d.png)

RustDesk welcomes contribution from everyone. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for help getting started.

[**FAQ**](https://github.com/rustdesk/rustdesk/wiki/FAQ)

[**BINARY DOWNLOAD**](https://github.com/rustdesk/rustdesk/releases)

[**NIGHTLY BUILD**](https://github.com/rustdesk/rustdesk/releases/tag/nightly)

[<img src="https://f-droid.org/badge/get-it-on.png"
    alt="Get it on F-Droid"
    height="80">](https://f-droid.org/en/packages/com.carriez.flutter_hbb)
[<img src="https://flathub.org/api/badge?svg&locale=en"
    alt="Get it on Flathub"
    height="80">](https://flathub.org/apps/com.rustdesk.RustDesk)

## Dependencies

Desktop versions use Flutter or Sciter (deprecated) for GUI, this tutorial is for Sciter only, since it is easier and more friendly to start. Check out our [CI](https://github.com/rustdesk/rustdesk/blob/master/.github/workflows/flutter-build.yml) for building Flutter version.

Please download Sciter dynamic library yourself.

[Windows](https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.win/x64/sciter.dll) |
[Linux](https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.lnx/x64/libsciter-gtk.so) |
[macOS](https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.osx/libsciter.dylib)

## Raw Steps to build

- Prepare your Rust development env and C++ build env

- Install [vcpkg](https://github.com/microsoft/vcpkg), and set `VCPKG_ROOT` env variable correctly

  - Windows: vcpkg install libvpx:x64-windows-static libyuv:x64-windows-static opus:x64-windows-static aom:x64-windows-static
  - Linux/macOS: vcpkg install libvpx libyuv opus aom

- run `cargo run`

## [Build](https://rustdesk.com/docs/en/dev/build/)

## How to Build on Linux

### Ubuntu 18 (Debian 10)

```sh
sudo apt install -y zip g++ gcc git curl wget nasm yasm libgtk-3-dev clang libxcb-randr0-dev libxdo-dev \
        libxfixes-dev libxcb-shape0-dev libxcb-xfixes0-dev libasound2-dev libpulse-dev cmake make \
        libclang-dev ninja-build libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libpam0g-dev
```

### openSUSE Tumbleweed

```sh
sudo zypper install gcc-c++ git curl wget nasm yasm gcc gtk3-devel clang libxcb-devel libXfixes-devel cmake alsa-lib-devel gstreamer-devel gstreamer-plugins-base-devel xdotool-devel pam-devel
```

### Fedora 28 (CentOS 8)

```sh
sudo yum -y install gcc-c++ git curl wget nasm yasm gcc gtk3-devel clang libxcb-devel libxdo-devel libXfixes-devel pulseaudio-libs-devel cmake alsa-lib-devel gstreamer1-devel gstreamer1-plugins-base-devel pam-devel
```

### Arch (Manjaro)

```sh
sudo pacman -Syu --needed unzip git cmake gcc curl wget yasm nasm zip make pkg-config clang gtk3 xdotool libxcb libxfixes alsa-lib pipewire
```

### Install vcpkg

```sh
git clone https://github.com/microsoft/vcpkg
cd vcpkg
git checkout 2023.04.15
cd ..
vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=$HOME/vcpkg
vcpkg/vcpkg install libvpx libyuv opus aom
```

### Fix libvpx (For Fedora)

```sh
cd vcpkg/buildtrees/libvpx/src
cd *
./configure
sed -i 's/CFLAGS+=-I/CFLAGS+=-fPIC -I/g' Makefile
sed -i 's/CXXFLAGS+=-I/CXXFLAGS+=-fPIC -I/g' Makefile
make
cp libvpx.a $HOME/vcpkg/installed/x64-linux/lib/
cd
```

### Build

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
git clone --recurse-submodules https://github.com/rustdesk/rustdesk
cd rustdesk
mkdir -p target/debug
wget https://raw.githubusercontent.com/c-smile/sciter-sdk/master/bin.lnx/x64/libsciter-gtk.so
mv libsciter-gtk.so target/debug
VCPKG_ROOT=$HOME/vcpkg cargo run
```

## How to build with Docker

Begin by cloning the repository and building the Docker container:

```sh
git clone https://github.com/rustdesk/rustdesk
cd rustdesk
git submodule update --init --recursive
docker build -t "rustdesk-builder" .
```

Then, each time you need to build the application, run the following command:

```sh
docker run --rm -it -v $PWD:/home/user/rustdesk -v rustdesk-git-cache:/home/user/.cargo/git -v rustdesk-registry-cache:/home/user/.cargo/registry -e PUID="$(id -u)" -e PGID="$(id -g)" rustdesk-builder
```

Note that the first build may take longer before dependencies are cached, subsequent builds will be faster. Additionally, if you need to specify different arguments to the build command, you may do so at the end of the command in the `<OPTIONAL-ARGS>` position. For instance, if you wanted to build an optimized release version, you would run the command above followed by `--release`. The resulting executable will be available in the target folder on your system, and can be run with:

```sh
target/debug/rustdesk
```

Or, if you're running a release executable:

```sh
target/release/rustdesk
```

Please ensure that you run these commands from the root of the RustDesk repository, or the application may not find the required resources. Also note that other cargo subcommands such as `install` or `run` are not currently supported via this method as they would install or run the program inside the container instead of the host.

## File Structure

- **[libs/hbb_common](https://github.com/rustdesk/rustdesk/tree/master/libs/hbb_common)**: video codec, config, tcp/udp wrapper, protobuf, fs functions for file transfer, and some other utility functions
- **[libs/scrap](https://github.com/rustdesk/rustdesk/tree/master/libs/scrap)**: screen capture
- **[libs/enigo](https://github.com/rustdesk/rustdesk/tree/master/libs/enigo)**: platform specific keyboard/mouse control
- **[libs/clipboard](https://github.com/rustdesk/rustdesk/tree/master/libs/clipboard)**: file copy and paste implementation for Windows, Linux, macOS.
- **[src/ui](https://github.com/rustdesk/rustdesk/tree/master/src/ui)**: obsolete Sciter UI (deprecated)
- **[src/server](https://github.com/rustdesk/rustdesk/tree/master/src/server)**: audio/clipboard/input/video services, and network connections
- **[src/client.rs](https://github.com/rustdesk/rustdesk/tree/master/src/client.rs)**: start a peer connection
- **[src/rendezvous_mediator.rs](https://github.com/rustdesk/rustdesk/tree/master/src/rendezvous_mediator.rs)**: Communicate with [rustdesk-server](https://github.com/rustdesk/rustdesk-server), wait for remote direct (TCP hole punching) or relayed connection
- **[src/platform](https://github.com/rustdesk/rustdesk/tree/master/src/platform)**: platform specific code
- **[flutter](https://github.com/rustdesk/rustdesk/tree/master/flutter)**: Flutter code for desktop and mobile
- **[flutter/web/js](https://github.com/rustdesk/rustdesk/tree/master/flutter/web/v1/js)**: JavaScript for Flutter web client

## Screenshots

![Connection Manager](https://github.com/rustdesk/rustdesk/assets/28412477/db82d4e7-c4bc-4823-8e6f-6af7eadf7651)

![Connected to a Windows PC](https://github.com/rustdesk/rustdesk/assets/28412477/9baa91e9-3362-4d06-aa1a-7518edcbd7ea)

![File Transfer](https://github.com/rustdesk/rustdesk/assets/28412477/39511ad3-aa9a-4f8c-8947-1cce286a46ad)

![TCP Tunneling](https://github.com/rustdesk/rustdesk/assets/28412477/78e8708f-e87e-4570-8373-1360033ea6c5)

