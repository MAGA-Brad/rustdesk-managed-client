"use strict";

const $ = (id) => document.getElementById(id);

// Matches the gateway's binary video header (session.rs): codec ids and their WebCodecs strings.
const CODECS = {
  1: { name: "vp9", strings: ["vp09.00.41.08", "vp09.00.10.08"] },
  2: { name: "av1", strings: ["av01.0.08M.08", "av01.0.04M.08"] },
  3: { name: "h264", strings: ["avc1.640033", "avc1.42E01F"] },
  4: { name: "vp8", strings: ["vp8"] },
};
const MOUSE = { MOVE: 0, DOWN: 1, UP: 2, WHEEL: 3 };
const LEFT = 1;
const RIGHT = 2;
// Trackpad mode: remote pixels moved per screen pixel of finger travel, on top of the display scale.
const TRACKPAD_SPEED = 1.5;
const TAP_MS = 300;
const DOUBLE_TAP_MS = 350;
const SCROLL_STEP = 24;
// Shown until the computer sends its own pointer image.
const ARROW = {
  url: "data:image/svg+xml," + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="14" height="22" viewBox="0 0 14 22"><path d="M1 1v17l4.5-4.2 3 6.8 2.6-1.2-3-6.6H14z" fill="#fff" stroke="#000" stroke-width="1.2"/></svg>'),
  hotx: 1, hoty: 1, w: 14, h: 22,
};
const BUTTONS = [1, 4, 2, 8, 16]; // browser button 0..4 -> left, middle, right, back, forward

let account = null;
let devices = [];
let refreshTimer = 0;
let current = null;
let supported = null;

function show(view) {
  for (const id of ["signin", "home", "session"]) $(id).hidden = id !== view;
}

async function api(path, body) {
  const options = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers["Content-Type"] = "application/json";
    options.headers["X-RDW"] = "1";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch { /* empty body */ }
  return { status: response.status, data };
}

// ---- sign-in -------------------------------------------------------------------------------

async function boot() {
  const me = await api("/api/me").catch(() => ({ status: 0, data: {} }));
  if (me.status === 200) {
    enterHome(me.data.account);
  } else {
    show("signin");
    $("username").focus();
  }
}

$("signinForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("signinButton");
  button.disabled = true;
  $("signinError").textContent = "";
  const result = await api("/api/login", {
    username: $("username").value.trim(),
    password: $("password").value,
    totp_code: $("totp").value.trim(),
  }).catch(() => ({ status: 0, data: { error: "RustDWeb could not be reached" } }));
  button.disabled = false;
  $("password").value = "";
  $("totp").value = "";
  if (result.status === 200) {
    enterHome(result.data.account);
  } else {
    $("signinError").textContent = result.data.error || "Sign-in failed";
  }
});

$("signoutButton").addEventListener("click", async () => {
  await api("/api/logout", {}).catch(() => {});
  account = null;
  clearInterval(refreshTimer);
  show("signin");
});

// ---- computers -----------------------------------------------------------------------------

function enterHome(acct) {
  account = acct || account;
  $("whoName").textContent = account ? account.display_name || account.username : "";
  show("home");
  loadDevices();
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { if (!$("home").hidden) loadDevices(); }, 30000);
}

async function loadDevices() {
  const result = await api("/api/devices").catch(() => ({ status: 0, data: {} }));
  if (result.status === 401) {
    clearInterval(refreshTimer);
    show("signin");
    $("signinError").textContent = result.data.error || "Your sign-in has ended";
    return;
  }
  if (result.status !== 200) {
    $("devicesEmpty").hidden = false;
    $("devicesEmpty").textContent = result.data.error || "RustDWeb could not load the computers";
    return;
  }
  devices = result.data.devices || [];
  renderDevices();
}

function renderDevices() {
  const term = $("search").value.trim().toLowerCase();
  const list = devices.filter((d) => !term
    || String(d.name).toLowerCase().includes(term)
    || String(d.hostname).toLowerCase().includes(term));
  const online = devices.filter((d) => d.online).length;
  $("deviceCount").textContent = `${online} of ${devices.length} online`;
  const ul = $("devices");
  ul.replaceChildren();
  for (const device of list) {
    const li = document.createElement("li");
    li.className = "device";
    const dot = document.createElement("span");
    dot.className = device.online ? "dot online" : "dot";
    dot.title = device.online ? "Online" : "Offline";
    const text = document.createElement("div");
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = device.name;
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = device.hostname || "";
    if (device.in_session_with) {
      const busy = document.createElement("span");
      busy.className = "busy";
      busy.textContent = ` · in a session with ${device.in_session_with}`;
      sub.append(busy);
    }
    text.append(name, sub);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "primary";
    button.textContent = "Connect";
    button.disabled = !device.online;
    button.addEventListener("click", () => askConnect(device));
    li.append(dot, text, button);
    ul.append(li);
  }
  $("devicesEmpty").hidden = list.length > 0;
  $("devicesEmpty").textContent = devices.length ? "No computers match." : "No computers are available.";
}

$("search").addEventListener("input", renderDevices);

let pending = null;
function askConnect(device) {
  pending = device;
  $("connectTitle").textContent = `Connect to ${device.name}`;
  $("pcPassword").value = "";
  $("pcTotp").value = "";
  $("connectDialog").showModal();
  $("pcPassword").focus();
}
$("connectCancel").addEventListener("click", () => $("connectDialog").close());
$("connectForm").addEventListener("submit", (event) => {
  event.preventDefault();
  const password = $("pcPassword").value;
  const totp = $("pcTotp").value.trim();
  $("pcPassword").value = "";
  $("pcTotp").value = "";
  $("connectDialog").close();
  if (pending) startSession(pending, password, totp);
});

// ---- session -------------------------------------------------------------------------------

async function detectCodecs() {
  if (!("VideoDecoder" in window)) return null;
  const found = {};
  for (const [id, codec] of Object.entries(CODECS)) {
    for (const string of codec.strings) {
      try {
        const result = await VideoDecoder.isConfigSupported({ codec: string, optimizeForLatency: true });
        if (result.supported) { found[id] = string; break; }
      } catch { /* not supported */ }
    }
  }
  return found;
}

let starting = 0;
async function startSession(device, password, totp) {
  if (current) current.end("Replaced by a new session");
  const attempt = ++starting;
  supported = supported || await detectCodecs();
  show("session");
  $("sessionName").textContent = device.name;
  if (!supported || Object.keys(supported).length === 0) {
    overlay("This browser can't show remote screens",
      "RustDWeb needs a current Chrome, Edge, Safari or Firefox (WebCodecs video decoding).", null, true);
    return;
  }
  // A browser can't read why a WebSocket handshake was refused, so ask first.
  $("sessionStatus").textContent = "Connecting";
  overlay(`Connecting to ${device.name}`, "Reaching the computer through RustDWeb.");
  const ready = await api(`/api/session/ready?id=${encodeURIComponent(device.id)}`)
    .catch(() => ({ status: 0, data: { error: "RustDWeb could not be reached" } }));
  // Another session was started, or the viewer left, while the answer was on its way.
  if (attempt !== starting || $("session").hidden) return;
  if (ready.status === 401) {
    clearInterval(refreshTimer);
    show("signin");
    $("signinError").textContent = ready.data.error || "Your sign-in has ended";
    return;
  }
  if (ready.status === 429) {
    $("sessionStatus").textContent = "Not connected";
    overlay("Try again later", ready.data.error || "Too many sessions were started. Wait a few minutes, then try again.", null, true);
    return;
  }
  if (ready.status !== 200) {
    $("sessionStatus").textContent = "Not connected";
    overlay("Can't start the session", ready.data.error || "RustDWeb could not start the session. Try again shortly.", null, true);
    return;
  }
  current = new RemoteSession(device, password, totp);
}

function overlay(title, text, form, back) {
  $("overlay").hidden = false;
  $("overlayTitle").textContent = title;
  $("overlayText").textContent = text || "";
  $("overlayForm").hidden = !form;
  $("overlayBack").hidden = !back;
  if (form) {
    $("overlayPasswordRow").hidden = !form.password;
    $("overlayCodeRow").hidden = !form.code;
    $("overlayPassword").value = "";
    $("overlayCode").value = "";
    (form.password ? $("overlayPassword") : $("overlayCode")).focus();
  }
}

class RemoteSession {
  constructor(device, password, totp) {
    this.device = device;
    this.ws = new WebSocket(`wss://${location.host}/api/session?id=${encodeURIComponent(device.id)}`);
    this.ws.binaryType = "arraybuffer";
    this.decoder = null;
    this.codec = 0;
    this.waitKey = true;
    this.displays = [];
    this.display = { x: 0, y: 0, width: 0, height: 0 };
    this.cursors = new Map();
    this.pressed = new Set();
    this.connected = false;
    this.opened = false;
    this.ended = false;
    this.pendingMove = null;
    this.wheel = { x: 0, y: 0 };
    this.cur = null;
    this.cursor = null;
    this.lastPointer = "mouse";
    this.touches = new Map();
    this.tp = { startAt: 0, maxTouches: 0, moved: false, lastTapAt: 0, dragArmed: false, dragging: false, scroll: { x: 0, y: 0 } };
    this.canvas = $("screen");
    this.ctx = this.canvas.getContext("2d", { alpha: false, desynchronized: true });
    this.status("Connecting");
    overlay(`Connecting to ${device.name}`, "Reaching the computer through RustDWeb.");
    this.ws.addEventListener("open", () => {
      // Ended (or replaced) while connecting: never start a session nobody can see.
      if (this.ended || current !== this) { this.ws.close(); return; }
      this.opened = true;
      this.send({ t: "start", codecs: Object.fromEntries(Object.entries(supported).map(([id]) => [CODECS[id].name, true])), password, totp });
    });
    this.ws.addEventListener("message", (event) => {
      if (this.ended || current !== this) return;
      if (typeof event.data === "string") this.onText(JSON.parse(event.data));
      else this.onVideo(event.data);
    });
    this.ws.addEventListener("close", () => this.end(this.closedReason
      || (this.opened ? "The connection to RustDWeb was lost" : "RustDWeb could not start the session. Try again shortly.")));
    this.bindInput();
  }

  send(message) {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(message));
  }

  status(text) { $("sessionStatus").textContent = text; }

  onText(m) {
    switch (m.t) {
      case "state":
        this.status("Connecting");
        break;
      case "need":
        if (m.what === "password_or_accept") {
          this.status("Waiting for acceptance");
          overlay(`Waiting for ${this.device.name}`,
            "The person at the computer has been asked to accept. Or sign in with the computer's own password.",
            { password: true, code: true });
          this.need = "password";
        } else if (m.what === "password") {
          this.status("Password needed");
          overlay("Computer password", m.error ? `${m.error}. Enter the computer's RDC password.` : "Enter the computer's RDC password.",
            { password: true, code: true });
          this.need = "password";
        } else if (m.what === "2fa") {
          this.status("Authenticator code needed");
          overlay("Computer authenticator code", m.error && m.error !== "2FA Required" ? `${m.error}. Try again.` : "Enter the 6-digit code for this computer.",
            { code: true });
          this.need = "2fa";
        }
        break;
      case "connected":
        this.connected = true;
        this.displays = m.displays || [];
        this.setDisplay(m.current || 0);
        this.fillDisplays();
        this.centerCursor();
        this.status(`Connected · ${m.platform || ""}`);
        $("overlay").hidden = true;
        this.canvas.focus();
        break;
      case "display":
        this.display = { x: m.x, y: m.y, width: m.width, height: m.height };
        $("displaySelect").value = String(m.display);
        this.waitKey = true;
        this.centerCursor();
        break;
      case "cursor": this.setCursor(m); break;
      case "cursorId": this.useCursor(m.id); break;
      case "cursorPos":
        if (!this.tp.dragging && this.touches.size === 0) {
          this.cur = { x: m.x, y: m.y };
          this.drawCursor();
        }
        break;
      case "permission":
        if (m.name === "Keyboard" && m.enabled === false) this.status("View only (the computer turned off input)");
        break;
      case "closed":
        this.closedReason = m.reason;
        break;
      default: break;
    }
  }

  onVideo(buffer) {
    const view = new DataView(buffer);
    if (buffer.byteLength < 12 || view.getUint8(0) !== 1) return;
    const codec = view.getUint8(1);
    const key = view.getUint8(2) === 1;
    if (!supported[codec]) return;
    if (codec !== this.codec || !this.decoder || this.decoder.state === "closed") this.newDecoder(codec);
    if (this.waitKey && !key) return;
    if (!key && this.decoder.decodeQueueSize > 6) {
      this.waitKey = true;
      this.send({ t: "refresh" });
      return;
    }
    this.waitKey = false;
    const pts = Number(view.getBigInt64(4, true));
    try {
      this.decoder.decode(new EncodedVideoChunk({ type: key ? "key" : "delta", timestamp: pts * 1000, data: new Uint8Array(buffer, 12) }));
    } catch {
      this.waitKey = true;
      this.send({ t: "refresh" });
    }
  }

  newDecoder(codec) {
    try { if (this.decoder && this.decoder.state !== "closed") this.decoder.close(); } catch { /* already closed */ }
    this.codec = codec;
    this.waitKey = true;
    this.decoder = new VideoDecoder({
      output: (frame) => this.draw(frame),
      error: () => { this.waitKey = true; this.decoder = null; this.send({ t: "refresh" }); },
    });
    this.decoder.configure({ codec: supported[codec], optimizeForLatency: true });
  }

  draw(frame) {
    if (this.canvas.width !== frame.displayWidth || this.canvas.height !== frame.displayHeight) {
      this.canvas.width = frame.displayWidth;
      this.canvas.height = frame.displayHeight;
      requestAnimationFrame(() => this.drawCursor());
    }
    this.ctx.drawImage(frame, 0, 0);
    frame.close();
  }

  setDisplay(index) {
    const d = this.displays[index];
    if (d) this.display = { x: d.x, y: d.y, width: d.width, height: d.height };
  }

  fillDisplays() {
    const select = $("displaySelect");
    select.replaceChildren();
    this.displays.forEach((d, i) => {
      const option = document.createElement("option");
      option.value = String(i);
      option.textContent = `Screen ${i + 1} (${d.width}×${d.height})`;
      select.append(option);
    });
    select.hidden = this.displays.length < 2;
  }

  setCursor(m) {
    try {
      const raw = atob(m.rgba);
      const bytes = new Uint8ClampedArray(raw.length);
      for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
      const canvas = document.createElement("canvas");
      canvas.width = m.width;
      canvas.height = m.height;
      canvas.getContext("2d").putImageData(new ImageData(bytes, m.width, m.height), 0, 0);
      const url = canvas.toDataURL("image/png");
      this.cursors.set(m.id, { css: `url(${url}) ${m.hotx} ${m.hoty}, default`, url, hotx: m.hotx, hoty: m.hoty, w: m.width, h: m.height });
      this.useCursor(m.id);
    } catch { /* keep the current cursor */ }
  }

  useCursor(id) {
    const cursor = this.cursors.get(id);
    if (!cursor) return;
    this.cursor = cursor;
    this.canvas.style.cursor = cursor.css;
    this.drawCursor();
  }

  // ---- trackpad mode ------------------------------------------------------------------

  trackpad() { return $("trackpadToggle").checked; }

  centerCursor() {
    const d = this.display;
    if (!d.width || !d.height) return;
    this.cur = { x: d.x + d.width / 2, y: d.y + d.height / 2 };
    this.drawCursor();
  }

  // The remote pointer, drawn over the screen (a touch screen has no pointer of its own).
  drawCursor() {
    const el = $("rcursor");
    const rect = this.canvas.getBoundingClientRect();
    if (!this.trackpad() || this.lastPointer === "mouse" || !this.connected || !this.cur || !this.canvas.width || !rect.width) {
      el.hidden = true;
      return;
    }
    const stage = $("stage");
    const srect = stage.getBoundingClientRect();
    const sx = rect.width / this.canvas.width;
    const sy = rect.height / this.canvas.height;
    const c = this.cursor || ARROW;
    const scale = Math.min(Math.max(sx, 0.6), 1);
    el.style.width = `${c.w * scale}px`;
    el.style.height = `${c.h * scale}px`;
    el.style.backgroundImage = `url("${c.url}")`;
    const left = rect.left - srect.left + stage.scrollLeft + (this.cur.x - this.display.x) * sx - c.hotx * scale;
    const top = rect.top - srect.top + stage.scrollTop + (this.cur.y - this.display.y) * sy - c.hoty * scale;
    el.style.transform = `translate(${left}px, ${top}px)`;
    el.hidden = false;
  }

  sendAtCursor(mask) {
    if (!this.connected || !this.cur) return;
    this.send({ t: "mouse", mask, x: Math.round(this.cur.x), y: Math.round(this.cur.y), mods: [] });
  }

  click(button) {
    this.sendAtCursor(MOUSE.DOWN | (button << 3));
    this.sendAtCursor(MOUSE.UP | (button << 3));
  }

  moveBy(dx, dy) {
    const rect = this.canvas.getBoundingClientRect();
    if (!rect.width || !this.canvas.width || !this.cur) return;
    const speed = TRACKPAD_SPEED * this.canvas.width / rect.width;
    const d = this.display;
    this.cur.x = Math.min(Math.max(this.cur.x + dx * speed, d.x), d.x + d.width - 1);
    this.cur.y = Math.min(Math.max(this.cur.y + dy * speed, d.y), d.y + d.height - 1);
    this.drawCursor();
    if (!this.tpMoveQueued) {
      this.tpMoveQueued = true;
      requestAnimationFrame(() => {
        this.tpMoveQueued = false;
        this.sendAtCursor(MOUSE.MOVE);
      });
    }
  }

  tpDown(e) {
    this.canvas.setPointerCapture(e.pointerId);
    const now = performance.now();
    if (this.touches.size === 0) {
      this.tp.startAt = now;
      this.tp.maxTouches = 0;
      this.tp.moved = false;
      this.tp.dragArmed = now - this.tp.lastTapAt < DOUBLE_TAP_MS;
      this.tp.scroll = { x: 0, y: 0 };
      if (!this.cur) this.centerCursor();
    }
    this.touches.set(e.pointerId, { x: e.clientX, y: e.clientY, sx: e.clientX, sy: e.clientY });
    this.tp.maxTouches = Math.max(this.tp.maxTouches, this.touches.size);
  }

  tpMove(e) {
    const t = this.touches.get(e.pointerId);
    if (!t) return;
    const dx = e.clientX - t.x;
    const dy = e.clientY - t.y;
    t.x = e.clientX;
    t.y = e.clientY;
    if (Math.hypot(e.clientX - t.sx, e.clientY - t.sy) > 8) this.tp.moved = true;
    if (this.touches.size === 1 && this.tp.maxTouches === 1) {
      // Double-tap and hold, then drag: the button stays down while the finger moves.
      if (this.tp.dragArmed && this.tp.moved && !this.tp.dragging) {
        this.tp.dragging = true;
        this.sendAtCursor(MOUSE.DOWN | (LEFT << 3));
      }
      this.moveBy(dx, dy);
    } else if (this.touches.size === 2) {
      // Two fingers scroll the content the way they move (finger up, page down).
      this.tp.scroll.x += dx / 2;
      this.tp.scroll.y += dy / 2;
      const step = (v) => (Math.abs(v) >= SCROLL_STEP ? (v < 0 ? -1 : 1) : 0);
      const sx = step(this.tp.scroll.x);
      const sy = step(this.tp.scroll.y);
      if (sx) this.tp.scroll.x = 0;
      if (sy) this.tp.scroll.y = 0;
      if (sx || sy) this.send({ t: "mouse", mask: MOUSE.WHEEL, x: sx, y: sy, mods: [] });
    }
  }

  tpUp(e, cancelled) {
    if (!this.touches.delete(e.pointerId) || this.touches.size > 0) return;
    const now = performance.now();
    if (this.tp.dragging) {
      this.tp.dragging = false;
      this.sendAtCursor(MOUSE.UP | (LEFT << 3));
    } else if (!cancelled && !this.tp.moved && now - this.tp.startAt < TAP_MS) {
      if (this.tp.maxTouches === 1) {
        this.click(LEFT);
        this.tp.lastTapAt = now;
      } else if (this.tp.maxTouches === 2) {
        this.click(RIGHT);
        this.tp.lastTapAt = 0;
      }
    }
  }

  // ---- input --------------------------------------------------------------------------

  point(event) {
    const rect = this.canvas.getBoundingClientRect();
    if (!rect.width || !rect.height || !this.canvas.width) return null;
    const x = Math.min(Math.max(event.clientX - rect.left, 0), rect.width - 1);
    const y = Math.min(Math.max(event.clientY - rect.top, 0), rect.height - 1);
    return {
      x: Math.round(x * this.canvas.width / rect.width) + this.display.x,
      y: Math.round(y * this.canvas.height / rect.height) + this.display.y,
    };
  }

  mods(event) {
    const list = [];
    if (event.ctrlKey) list.push("ctrl");
    if (event.shiftKey) list.push("shift");
    if (event.altKey) list.push("alt");
    if (event.metaKey) list.push("meta");
    return list;
  }

  mouse(type, button, event) {
    if (!this.connected) return;
    const p = this.point(event);
    if (!p) return;
    this.cur = { x: p.x, y: p.y };
    this.send({ t: "mouse", mask: type | (button << 3), x: p.x, y: p.y, mods: this.mods(event) });
  }

  usesTrackpad(e) {
    this.lastPointer = e.pointerType === "touch" ? "touch" : "mouse";
    return this.trackpad() && e.pointerType === "touch";
  }

  bindInput() {
    const c = this.canvas;
    this.listeners = [
      [c, "pointermove", (e) => {
        if (this.usesTrackpad(e)) { this.tpMove(e); return; }
        this.pendingMove = e;
        if (!this.moveQueued) {
          this.moveQueued = true;
          requestAnimationFrame(() => {
            this.moveQueued = false;
            if (this.pendingMove) this.mouse(MOUSE.MOVE, 0, this.pendingMove);
            this.pendingMove = null;
          });
        }
      }],
      [c, "pointerdown", (e) => {
        // Keep the on-screen keyboard up while a touch drives the pointer.
        if (!(e.pointerType === "touch" && document.activeElement === $("kbd"))) c.focus();
        if (this.usesTrackpad(e)) { e.preventDefault(); this.tpDown(e); this.drawCursor(); return; }
        this.drawCursor();
        c.setPointerCapture(e.pointerId);
        this.mouse(MOUSE.DOWN, BUTTONS[e.button] || 1, e);
        e.preventDefault();
      }],
      [c, "pointerup", (e) => {
        e.preventDefault();
        if (this.usesTrackpad(e)) { this.tpUp(e, false); return; }
        this.mouse(MOUSE.UP, BUTTONS[e.button] || 1, e);
      }],
      [c, "pointercancel", (e) => { if (this.touches.has(e.pointerId)) this.tpUp(e, true); }],
      [window, "resize", () => this.drawCursor()],
      [c, "contextmenu", (e) => e.preventDefault()],
      [c, "wheel", (e) => {
        e.preventDefault();
        if (!this.connected) return;
        const scale = e.deltaMode === 0 ? 1 : 50;
        this.wheel.x += e.deltaX * scale;
        this.wheel.y += e.deltaY * scale;
        const step = (v) => (Math.abs(v) >= 50 ? (v > 0 ? -1 : 1) : 0);
        const sx = step(this.wheel.x);
        const sy = step(this.wheel.y);
        if (sx) this.wheel.x = 0;
        if (sy) this.wheel.y = 0;
        if (sx || sy) this.send({ t: "mouse", mask: MOUSE.WHEEL, x: sx, y: sy, mods: this.mods(e) });
      }, { passive: false }],
      [c, "keydown", (e) => {
        if (!this.connected || e.isComposing) return;
        e.preventDefault();
        this.pressed.add(e.code);
        this.send({ t: "key", code: e.code, down: true });
      }],
      [c, "keyup", (e) => {
        if (!this.connected) return;
        e.preventDefault();
        this.pressed.delete(e.code);
        this.send({ t: "key", code: e.code, down: false });
      }],
      [c, "blur", () => this.releaseKeys()],
      [document, "visibilitychange", () => { if (document.hidden) this.releaseKeys(); }],
    ];
    for (const [target, type, handler, options] of this.listeners) target.addEventListener(type, handler, options);
  }

  tapKey(code) {
    this.send({ t: "key", code, down: true });
    this.send({ t: "key", code, down: false });
  }

  typeText(text) {
    const parts = text.split(/\r?\n/);
    parts.forEach((part, i) => {
      if (i > 0) this.tapKey("Enter");
      for (let at = 0; at < part.length; at += 256) this.send({ t: "text", s: part.slice(at, at + 256) });
    });
  }

  releaseKeys() {
    for (const code of this.pressed) this.send({ t: "key", code, down: false });
    this.pressed.clear();
  }

  end(reason) {
    if (this.ended) return;
    this.ended = true;
    this.releaseKeys();
    for (const [target, type, handler, options] of this.listeners || []) target.removeEventListener(type, handler, options);
    try { if (this.decoder && this.decoder.state !== "closed") this.decoder.close(); } catch { /* closed */ }
    if (this.ws.readyState === WebSocket.OPEN) {
      this.send({ t: "close" });
      this.ws.close();
    } else if (this.ws.readyState === WebSocket.CONNECTING) this.ws.close();
    this.canvas.style.cursor = "";
    $("rcursor").hidden = true;
    if (current === this) {
      current = null;
      this.status("Disconnected");
      if (!$("session").hidden) overlay("Session ended", reason, null, true);
    }
  }
}

$("overlayForm").addEventListener("submit", (event) => {
  event.preventDefault();
  if (!current) return;
  const password = $("overlayPassword").value;
  const code = $("overlayCode").value.trim();
  $("overlayPassword").value = "";
  $("overlayCode").value = "";
  if (current.need === "2fa") {
    if (code.length === 6) current.send({ t: "2fa", code });
  } else if (password) {
    current.send({ t: "password", password, totp: code });
  }
  overlay("Signing in", `Checking with ${current.device.name}.`);
});

$("overlayBack").addEventListener("click", () => { if (current) current.end("Closed"); enterHome(); });
$("disconnectButton").addEventListener("click", () => { if (current) current.end("You disconnected"); enterHome(); });
$("cadButton").addEventListener("click", () => { if (current) { current.send({ t: "cad" }); current.canvas.focus(); } });
$("displaySelect").addEventListener("change", (e) => {
  if (!current) return;
  const index = Number(e.target.value);
  current.setDisplay(index);
  current.waitKey = true;
  current.send({ t: "display", index });
  current.canvas.focus();
});
$("fitButton").addEventListener("click", () => {
  const fit = $("stage").classList.toggle("fit");
  $("fitButton").setAttribute("aria-pressed", String(fit));
  $("fitButton").textContent = fit ? "Fit to window" : "Actual size";
  if (current) requestAnimationFrame(() => current.drawCursor());
});
$("trackpadToggle").addEventListener("change", () => {
  if (!current) return;
  if (!current.cur) current.centerCursor();
  current.drawCursor();
  current.canvas.focus();
});
$("stage").addEventListener("scroll", () => { if (current) current.drawCursor(); });
$("fullscreenButton").addEventListener("click", async () => {
  if (document.fullscreenElement) {
    await document.exitFullscreen().catch(() => {});
    return;
  }
  await $("session").requestFullscreen().catch(() => {});
  // In full screen, Chromium lets the page receive shortcuts like Alt+Tab and Ctrl+W.
  if (navigator.keyboard && navigator.keyboard.lock) navigator.keyboard.lock().catch(() => {});
  if (current) current.canvas.focus();
});
window.addEventListener("beforeunload", () => { if (current) current.end("Page closed"); });

// ---- on-screen keyboard ----------------------------------------------------------------------
// Phone and tablet keyboards don't report physical keys (and autocorrect rewrites words), so the
// Keyboard button focuses a hidden field and each change to it is replayed on the computer:
// removed characters as Backspace, line breaks as Enter, new text typed as text.

const KBD_PAD = " ".repeat(40);
let kbdLast = "";
let kbdComposing = false;

function kbdReset() {
  const k = $("kbd");
  k.value = KBD_PAD;
  k.setSelectionRange(k.value.length, k.value.length);
  kbdLast = k.value;
}

if (navigator.maxTouchPoints > 0) $("keyboardButton").hidden = false;

$("keyboardButton").addEventListener("click", () => {
  const k = $("kbd");
  if (document.activeElement === k) {
    k.blur();
  } else {
    kbdReset();
    k.focus({ preventScroll: true });
  }
});

$("kbd").addEventListener("focus", () => $("keyboardButton").setAttribute("aria-pressed", "true"));
$("kbd").addEventListener("blur", () => $("keyboardButton").setAttribute("aria-pressed", "false"));
$("kbd").addEventListener("compositionstart", () => { kbdComposing = true; });
$("kbd").addEventListener("compositionend", () => { kbdComposing = false; });

$("kbd").addEventListener("input", () => {
  const k = $("kbd");
  const now = k.value;
  if (!current || !current.connected) { kbdReset(); return; }
  let same = 0;
  const max = Math.min(kbdLast.length, now.length);
  while (same < max && kbdLast[same] === now[same]) same++;
  for (let i = kbdLast.length - same; i > 0; i--) current.tapKey("Backspace");
  const added = now.slice(same);
  if (added) current.typeText(added);
  kbdLast = now;
  // Keep a cushion to delete into, without letting the field grow; never mid-word.
  if (!kbdComposing && (now.length < 8 || now.length > 200)) kbdReset();
});

// A hardware keyboard on a tablet: keys that don't type text go through as keys.
const KBD_KEYS = new Set(["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Escape", "Tab", "Delete",
  "Home", "End", "PageUp", "PageDown", "Insert"]);
$("kbd").addEventListener("keydown", (e) => {
  if (!current || !current.connected || e.isComposing || e.keyCode === 229) return;
  const shortcut = e.ctrlKey || e.metaKey || e.altKey;
  if (KBD_KEYS.has(e.code) || /^F\d+$/.test(e.code) || (shortcut && e.code)) {
    e.preventDefault();
    current.send({ t: "key", code: e.code, down: true });
    current.pressed.add(e.code);
  }
});
$("kbd").addEventListener("keyup", (e) => {
  if (!current || !current.pressed.has(e.code)) return;
  e.preventDefault();
  current.pressed.delete(e.code);
  current.send({ t: "key", code: e.code, down: false });
});

boot();
