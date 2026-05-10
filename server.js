const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const ADMIN_PIN = process.env.ADMIN_PIN || "1234";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || crypto.randomBytes(24).toString("hex");
const DATA_FILE = path.join(__dirname, "data.json");

let state = loadState();

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch (_) {
    return { devices: {}, commands: {} };
  }
}

function saveState() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2));
}

function send(res, status, body) {
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
  });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => {
      data += chunk;
      if (data.length > 1_000_000) {
        req.destroy();
        reject(new Error("Request body too large"));
      }
    });
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function getAuthToken(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
}

function requireAdmin(req, res) {
  if (getAuthToken(req) !== ADMIN_TOKEN) {
    send(res, 401, { error: "Unauthorized" });
    return false;
  }
  return true;
}

function now() {
  return new Date().toISOString();
}

function upsertDevice(deviceId, patch) {
  const existing = state.devices[deviceId] || {};
  state.devices[deviceId] = {
    id: deviceId,
    name: patch.name || existing.name || deviceId,
    role: patch.role || existing.role || "user",
    isAdminActive: Boolean(patch.isAdminActive ?? existing.isAdminActive),
    isDeviceOwner: Boolean(patch.isDeviceOwner ?? existing.isDeviceOwner),
    isUninstallBlocked: Boolean(patch.isUninstallBlocked ?? existing.isUninstallBlocked),
    isEmiLocked: Boolean(patch.isEmiLocked ?? existing.isEmiLocked),
    lastCommandStatus: existing.lastCommandStatus || "",
    lastCommandError: existing.lastCommandError || "",
    lastSeenAt: now()
  };
  if (!state.commands[deviceId]) state.commands[deviceId] = [];
  saveState();
  return state.devices[deviceId];
}

function publicDevice(device) {
  return {
    id: device.id,
    name: device.name,
    role: device.role,
    isAdminActive: device.isAdminActive,
    isDeviceOwner: device.isDeviceOwner,
    isUninstallBlocked: device.isUninstallBlocked,
    isEmiLocked: device.isEmiLocked,
    lastCommandStatus: device.lastCommandStatus || "",
    lastCommandError: device.lastCommandError || "",
    lastSeenAt: device.lastSeenAt
  };
}

function createCommand(deviceId, type) {
  const command = {
    id: crypto.randomUUID(),
    type,
    status: "pending",
    createdAt: now(),
    completedAt: null
  };
  if (!state.commands[deviceId]) state.commands[deviceId] = [];
  state.commands[deviceId].push(command);
  saveState();
  return command;
}

async function route(req, res) {
  if (req.method === "OPTIONS") return send(res, 200, {});

  const url = new URL(req.url, `http://${req.headers.host}`);
  const parts = url.pathname.split("/").filter(Boolean);

  if (req.method === "GET" && url.pathname === "/health") {
    return send(res, 200, { ok: true, time: now() });
  }

  if (req.method === "POST" && url.pathname === "/api/admin/login") {
    const body = await readJson(req);
    if (body.pin !== ADMIN_PIN) return send(res, 401, { error: "Invalid PIN" });
    return send(res, 200, { token: ADMIN_TOKEN });
  }

  if (req.method === "GET" && url.pathname === "/api/admin/devices") {
    if (!requireAdmin(req, res)) return;
    return send(res, 200, { devices: Object.values(state.devices).map(publicDevice) });
  }

  if (
    req.method === "POST" &&
    parts.length === 5 &&
    parts[0] === "api" &&
    parts[1] === "admin" &&
    parts[2] === "devices" &&
    parts[4] === "commands"
  ) {
    if (!requireAdmin(req, res)) return;
    const deviceId = decodeURIComponent(parts[3]);
    if (!state.devices[deviceId]) return send(res, 404, { error: "Device not found" });
    const body = await readJson(req);
    const type = String(body.type || "").toUpperCase();
    if (!["PROTECT", "DISABLE", "LOCK", "UNLOCK"].includes(type)) {
      return send(res, 400, { error: "Unsupported command type" });
    }
    return send(res, 201, { command: createCommand(deviceId, type) });
  }

  if (req.method === "POST" && url.pathname === "/api/devices/register") {
    const body = await readJson(req);
    const deviceId = String(body.id || "").trim();
    if (!deviceId) return send(res, 400, { error: "Device id is required" });
    return send(res, 200, { device: publicDevice(upsertDevice(deviceId, body)) });
  }

  if (
    req.method === "POST" &&
    parts.length === 4 &&
    parts[0] === "api" &&
    parts[1] === "devices" &&
    parts[3] === "status"
  ) {
    const deviceId = decodeURIComponent(parts[2]);
    const body = await readJson(req);
    return send(res, 200, { device: publicDevice(upsertDevice(deviceId, body)) });
  }

  if (
    req.method === "GET" &&
    parts.length === 5 &&
    parts[0] === "api" &&
    parts[1] === "devices" &&
    parts[3] === "commands" &&
    parts[4] === "pending"
  ) {
    const deviceId = decodeURIComponent(parts[2]);
    if (!state.commands[deviceId]) state.commands[deviceId] = [];
    const commands = state.commands[deviceId].filter(command => command.status === "pending");
    return send(res, 200, { commands });
  }

  if (
    req.method === "POST" &&
    parts.length === 6 &&
    parts[0] === "api" &&
    parts[1] === "devices" &&
    parts[3] === "commands" &&
    parts[5] === "ack"
  ) {
    const deviceId = decodeURIComponent(parts[2]);
    const commandId = decodeURIComponent(parts[4]);
    const body = await readJson(req);
    const commands = state.commands[deviceId] || [];
    const command = commands.find(item => item.id === commandId);
    if (!command) return send(res, 404, { error: "Command not found" });
    command.status = body.status === "failed" ? "failed" : "completed";
    command.error = body.error || "";
    command.completedAt = now();
    if (state.devices[deviceId]) {
      state.devices[deviceId].lastCommandStatus = `${command.type}: ${command.status}`;
      state.devices[deviceId].lastCommandError = command.error;
      state.devices[deviceId].lastSeenAt = now();
    }
    saveState();
    return send(res, 200, { command });
  }

  send(res, 404, { error: "Not found" });
}

const server = http.createServer((req, res) => {
  route(req, res).catch(error => send(res, 500, { error: error.message }));
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`RCA backend listening on http://0.0.0.0:${PORT}`);
  console.log(`Admin PIN: ${ADMIN_PIN}`);
  console.log(`Admin token for this run: ${ADMIN_TOKEN}`);
});
