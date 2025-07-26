const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const { exec } = require("child_process");

const app = express();
const PORT = 1000;

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const USERS_FILE = path.join(__dirname, "users.json");
const PROJECTS_FILE = path.join(__dirname, "projects.json");
const LOGS_FILE = path.join(__dirname, "logs.json");

function load(file, fallback = {}) {
  try {
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : fallback;
  } catch {
    return fallback;
  }
}

function save(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
  } catch {}
}

function sanitizeCommands(str) {
  return str
    .split(",")
    .map((cmd) => cmd.trim().replace(/\s+/g, " "))
    .filter(Boolean);
}

// Routes
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/status", (req, res) => {
  res.json({ initialized: fs.existsSync(USERS_FILE) });
});

app.post("/api/setup", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username and password required." });

  if (fs.existsSync(USERS_FILE)) {
    return res.status(400).json({ message: "Already initialized." });
  }

  save(USERS_FILE, { username, password });
  res.json({ message: "Setup complete." });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const users = load(USERS_FILE);

  if (users.username === username && users.password === password) {
    return res.json({ message: "Login successful." });
  }

  res.status(401).json({ message: "Invalid credentials." });
});

app.post("/api/project", (req, res) => {
  const { name, repo, secret, commands, workingDir } = req.body;
  if (!name || !repo || !secret || !workingDir)
    return res.status(400).json({ message: "Missing fields." });

  const projects = load(PROJECTS_FILE);
  if (projects[name]) return res.status(409).json({ message: "Project exists." });

  projects[name] = {
    repo,
    secret,
    commands: sanitizeCommands(commands),
    workingDir,
  };

  save(PROJECTS_FILE, projects);
  res.json({ message: "Project saved." });
});

app.put("/api/project/:name", (req, res) => {
  const name = req.params.name;
  const { repo, secret, commands, workingDir } = req.body;

  const projects = load(PROJECTS_FILE);
  if (!projects[name]) return res.status(404).json({ message: "Not found." });

  projects[name] = {
    repo,
    secret,
    commands: sanitizeCommands(commands),
    workingDir,
  };

  save(PROJECTS_FILE, projects);
  res.json({ message: "Project updated." });
});

app.delete("/api/project/:name", (req, res) => {
  const name = req.params.name;
  const projects = load(PROJECTS_FILE);
  if (!projects[name]) return res.status(404).json({ message: "Not found." });

  delete projects[name];
  save(PROJECTS_FILE, projects);
  res.json({ message: "Project deleted." });
});

app.get("/api/projects", (req, res) => {
  res.json(load(PROJECTS_FILE));
});

app.get("/api/logs", (req, res) => {
  res.json(load(LOGS_FILE, []));
});

app.post("/webhook", (req, res) => {
  const signature = req.headers["x-hub-signature-256"];
  const payload = req.body;

  const repoUrl = payload?.repository?.html_url?.replace(/\.git$/, "") || "";
  const projects = load(PROJECTS_FILE);

  const project = Object.values(projects).find(
    (p) => p.repo.replace(/\.git$/, "") === repoUrl
  );

  if (!project) return res.status(400).send("Project not found");

  const expectedSig =
    "sha256=" + crypto.createHmac("sha256", project.secret).update(req.rawBody).digest("hex");

  if (expectedSig !== signature) return res.status(403).send("Invalid signature");

  const logEntry = {
    time: new Date().toISOString(),
    repo: project.repo,
    branch: payload.ref,
    commit: payload.head_commit?.message,
    author: payload.pusher?.name,
    status: "started",
    output: [],
  };

  const logs = load(LOGS_FILE, []);
  logs.unshift(logEntry);
  save(LOGS_FILE, logs.slice(0, 100));

  const commandsToExecute = [...(project.commands || [])];
  const projectExecDir = path.isAbsolute(project.workingDir)
    ? project.workingDir
    : path.join(__dirname, project.workingDir);

  let commandIndex = 0;
  const executeNext = () => {
    if (commandIndex >= commandsToExecute.length) {
      const idx = logs.findIndex((l) => l.time === logEntry.time);
      if (idx !== -1 && logs[idx].status !== "failed") {
        logs[idx].status = "completed";
        save(LOGS_FILE, logs);
      }
      return console.log(`✅ All commands for ${project.repo} done.`);
    }

    const cmd = commandsToExecute[commandIndex];
    console.log(`⚙️ Running: ${cmd} in ${projectExecDir}`);

    exec(cmd, { cwd: projectExecDir }, (err, stdout, stderr) => {
      const idx = logs.findIndex((l) => l.time === logEntry.time);
      if (idx !== -1) {
        logs[idx].output.push({
          command: cmd,
          stdout,
          stderr,
          error: err ? err.message : null,
        });

        if (err) logs[idx].status = "failed";
        save(LOGS_FILE, logs);
      }

      commandIndex++;
      executeNext();
    });
  };

  executeNext();
  res.send("OK");
});

app.listen(PORT, () =>
  console.log(`✅ Webhook CI/CD server running at http://localhost:${PORT}`)
);
