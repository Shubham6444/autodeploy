const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const { exec } = require("child_process");

const app = express();
const PORT = 1000;

// Middleware to parse JSON and raw body for webhook signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

const USERS_FILE = path.join(__dirname, "users.json");
const PROJECTS_FILE = path.join(__dirname, "projects.json");
const LOGS_FILE = path.join(__dirname, "logs.json");

function load(file, fallback = {}) {
  try {
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : fallback;
  } catch (err) {
    console.error(`Error loading ${file}:`, err.message);
    return fallback;
  }
}

function save(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error(`Error saving ${file}:`, err.message);
  }
}

function sanitizeCommands(str) {
  return str
    .split(",")
    .map((cmd) => cmd.trim().replace(/\s+/g, " "))
    .filter(Boolean);
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/status", (req, res) => {
  res.json({ initialized: fs.existsSync(USERS_FILE) });
});

app.post("/api/setup", (req, res) => {
  const { username, password } = req.body;
  if (fs.existsSync(USERS_FILE)) {
    return res.status(400).json({ message: "Server already initialized." });
  }
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }
  save(USERS_FILE, { username, password });
  res.json({ message: "Setup complete." });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const users = load(USERS_FILE);
  if (!users.username || !users.password) {
    return res.status(400).json({ message: "Server not set up." });
  }
  if (users.username === username && users.password === password) {
    return res.json({ message: "Login successful." });
  }
  res.status(401).json({ message: "Invalid credentials." });
});

app.post("/api/project", (req, res) => {
  const { name, repo, secret, commands, workingDir } = req.body;
  if (!name || !repo || !secret || !workingDir) {
    return res.status(400).json({ message: "All fields are required." });
  }
  const projects = load(PROJECTS_FILE);
  if (projects[name]) {
    return res.status(409).json({ message: `Project '${name}' already exists.` });
  }
  projects[name] = { repo, secret, commands: sanitizeCommands(commands), workingDir };
  save(PROJECTS_FILE, projects);
  res.json({ message: "Project saved." });
});

app.put("/api/project/:name", (req, res) => {
  const name = req.params.name;
  const { repo, secret, commands, workingDir } = req.body;
  const projects = load(PROJECTS_FILE);
  if (!projects[name]) {
    return res.status(404).json({ message: "Project not found." });
  }
  projects[name] = { repo, secret, commands: sanitizeCommands(commands), workingDir };
  save(PROJECTS_FILE, projects);
  res.json({ message: "Project updated." });
});

app.delete("/api/project/:name", (req, res) => {
  const name = req.params.name;
  const projects = load(PROJECTS_FILE);
  if (!projects[name]) {
    return res.status(404).json({ message: "Project not found." });
  }
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
  const event = req.headers["x-github-event"];
  const signature = req.headers["x-hub-signature-256"];
  const payload = req.body;

  const repoUrl =
    payload?.repository?.html_url?.replace(/\.git$/, "") || null;

  const projects = load(PROJECTS_FILE);
  const project = Object.values(projects).find((p) => p.repo.replace(/\.git$/, "") === repoUrl);

  if (!project) {
    console.warn(`Webhook received for unknown repository: ${repoUrl}`);
    return res.status(400).send("Project not found.");
  }

  const expectedSig =
    "sha256=" + crypto.createHmac("sha256", project.secret).update(req.rawBody).digest("hex");

  if (signature !== expectedSig) {
    console.error("Invalid signature.");
    return res.status(403).send("Invalid signature.");
  }

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

  const projectExecDir = path.isAbsolute(project.workingDir)
    ? project.workingDir
    : path.join(__dirname, project.workingDir);

  const commandsToExecute = Array.isArray(project.commands) ? [...project.commands] : [];

  if (!fs.existsSync(projectExecDir)) {
    console.log(`Creating working directory: ${projectExecDir}`);
    fs.mkdirSync(projectExecDir, { recursive: true });
  }

  const gitRepoPath = path.join(projectExecDir, ".git");
  let workingDirectory;

  if (!fs.existsSync(gitRepoPath)) {
    const parentDir = path.dirname(projectExecDir);
    const repoName = path.basename(projectExecDir);
    const cloneCmd = `sudo git clone ${project.repo} ${repoName}`;
    commandsToExecute.unshift(cloneCmd);
    workingDirectory = parentDir;

    logEntry.output.push({
      command: cloneCmd,
      stdout: "",
      stderr: "",
      error: null,
    });

    console.log(`🚀 Cloning ${project.repo} into ${projectExecDir}`);
  } else {
    const pullCmd = "git pull";
    commandsToExecute.unshift(pullCmd);
    workingDirectory = projectExecDir;

    logEntry.output.push({
      command: pullCmd,
      stdout: "",
      stderr: "",
      error: null,
    });

    console.log(`🚀 Pulling latest changes in ${projectExecDir}`);
  }

  let commandIndex = 0;

  const executeNextCommand = () => {
    if (commandIndex >= commandsToExecute.length) {
      const logIdx = logs.findIndex((l) => l.time === logEntry.time);
      if (logIdx !== -1 && logs[logIdx].status !== "failed") {
        logs[logIdx].status = "completed";
        save(LOGS_FILE, logs);
      }
      console.log(`🎉 All commands for ${project.repo} finished.`);
      return;
    }

    const cmd = commandsToExecute[commandIndex];
    const currentCwd =
      commandIndex === 0 && cmd.startsWith("sudo git clone")
        ? path.dirname(projectExecDir)
        : projectExecDir;

    console.log(`⚙️ Running: ${cmd} in ${currentCwd}`);
    const child = exec(cmd, { cwd: currentCwd }, (err, stdout, stderr) => {
      const logIdx = logs.findIndex((l) => l.time === logEntry.time);
      if (logIdx !== -1) {
        logs[logIdx].output.push({
          command: cmd,
          stdout,
          stderr,
          error: err ? err.message : null,
        });
        if (err) {
          logs[logIdx].status = "failed";
          console.error(`❌ ${cmd}:`, err.message);
        } else {
          console.log(`✅ ${cmd}: Success`);
        }
        save(LOGS_FILE, logs);
      }

      commandIndex++;
      executeNextCommand();
    });

    child.stdout.on("data", (data) => {
      console.log(`[stdout] ${cmd}: ${data}`);
    });
    child.stderr.on("data", (data) => {
      console.error(`[stderr] ${cmd}: ${data}`);
    });
  };

  executeNextCommand();
  res.send("OK");
});

app.listen(PORT, () =>
  console.log(`✅ CI/CD Server running at http://localhost:${PORT}`)
);
