const express = require("express")
const fs = require("fs")
const crypto = require("crypto")
const path = require("path")
const { exec } = require("child_process")

const app = express()
const PORT = 1000

// Middleware to parse JSON and raw body for webhook signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf
    },
  }),
)
app.use(express.urlencoded({ extended: true }))

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, "public")))

const USERS_FILE = path.join(__dirname, "users.json")
const PROJECTS_FILE = path.join(__dirname, "projects.json")
const LOGS_FILE = path.join(__dirname, "logs.json")

function load(file, fallback = {}) {
  try {
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : fallback
  } catch (error) {
    console.error(`Error loading ${file}:`, error.message)
    return fallback
  }
}

function save(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8")
  } catch (error) {
    console.error(`Error saving ${file}:`, error.message)
  }
}

function sanitizeCommands(str) {
  return str
    .split(",")
    .map((cmd) => cmd.trim().replace(/\s+/g, " "))
    .filter(Boolean)
}

// Root route to serve the HTML UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"))
})

// NEW: Endpoint to check server initialization status
app.get("/api/status", (req, res) => {
  if (fs.existsSync(USERS_FILE)) {
    res.json({ initialized: true })
  } else {
    res.json({ initialized: false })
  }
})

// API Endpoints
app.post("/api/setup", (req, res) => {
  const { username, password } = req.body
  if (fs.existsSync(USERS_FILE)) {
    return res.status(400).json({ message: "Server already initialized." })
  }
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." })
  }
  save(USERS_FILE, { username, password })
  res.json({ message: "Setup complete." })
})

app.post("/api/login", (req, res) => {
  const { username, password } = req.body
  const users = load(USERS_FILE)
  if (!users.username || !users.password) {
    return res.status(400).json({ message: "Server not set up. Please run setup first." })
  }
  if (users.username === username && users.password === password) {
    return res.json({ message: "Login successful." })
  }
  res.status(401).json({ message: "Invalid username or password." })
})

// Add new project
app.post("/api/project", (req, res) => {
  const { name, repo, secret, commands, workingDir } = req.body
  if (!name || !repo || !secret || !workingDir) {
    return res.status(400).json({ message: "Project name, repository, secret, and working directory are required." })
  }
  const projects = load(PROJECTS_FILE)
  if (projects[name]) {
    return res.status(409).json({ message: `Project with name '${name}' already exists.` })
  }
  projects[name] = { repo, secret, commands: sanitizeCommands(commands), workingDir }
  save(PROJECTS_FILE, projects)
  res.json({ message: "Project saved successfully." })
})

// Update existing project
app.put("/api/project/:name", (req, res) => {
  const projectName = req.params.name
  const { repo, secret, commands, workingDir } = req.body
  if (!repo || !secret || !commands || !workingDir) {
    return res.status(400).json({ message: "Repository, secret, commands, and working directory are required." })
  }
  const projects = load(PROJECTS_FILE)
  if (!projects[projectName]) {
    return res.status(404).json({ message: `Project '${projectName}' not found.` })
  }
  projects[projectName] = { repo, secret, commands: sanitizeCommands(commands), workingDir }
  save(PROJECTS_FILE, projects)
  res.json({ message: `Project '${projectName}' updated successfully.` })
})

// Delete project
app.delete("/api/project/:name", (req, res) => {
  const projectName = req.params.name
  const projects = load(PROJECTS_FILE)
  if (!projects[projectName]) {
    return res.status(404).json({ message: `Project '${projectName}' not found.` })
  }
  delete projects[projectName]
  save(PROJECTS_FILE, projects)
  res.json({ message: `Project '${projectName}' deleted successfully.` })
})

app.get("/api/projects", (req, res) => {
  res.json(load(PROJECTS_FILE))
})

app.get("/api/logs", (req, res) => {
  res.json(load(LOGS_FILE, []))
})

// Webhook endpoint
app.post("/webhook", (req, res) => {
  const event = req.headers["x-github-event"]
  console.log(event)
  const signature = req.headers["x-hub-signature-256"]
  const payload = req.body

const repoUrl =
  payload && payload.repository && payload.repository.html_url
    ? payload.repository.html_url.replace(/\.git$/, "")
    : null
  const projects = load(PROJECTS_FILE)

  const project = Object.values(projects).find((p) => p.repo.replace(/\.git$/, "") === repoUrl)

  if (!project) {
    console.warn(`Webhook received for unknown repository: ${repoUrl}`)
    return res.status(400).send("Project not found")
  }

  // Verify webhook signature
  const expectedSig = "sha256=" + crypto.createHmac("sha256", project.secret).update(req.rawBody).digest("hex")
  if (expectedSig !== signature) {
    console.error(`Invalid signature for project ${project.name}. Expected: ${expectedSig}, Received: ${signature}`)
    return res.status(403).send("Invalid signature")
  }

  const logEntry = {
    time: new Date().toISOString(),
    repo: project.repo,
    branch: payload.ref,
    commit: payload.head_commit?.message,
    author: payload.pusher?.name,
    status: "started",
    output: [],
  }

  const logs = load(LOGS_FILE, [])
  logs.unshift(logEntry) // Add to the beginning
  save(LOGS_FILE, logs.slice(0, 100)) // Keep only the latest 100 logs

const projectExecDir = path.isAbsolute(project.workingDir)
  ? project.workingDir
  : path.join(__dirname, project.workingDir)
  const commandsToExecute = Array.isArray(project.commands) ? [...project.commands] : [] // Clone array

  // Ensure the working directory exists
  if (!fs.existsSync(projectExecDir)) {
    console.log(`Creating working directory: ${projectExecDir}`)
    fs.mkdirSync(projectExecDir, { recursive: true })
  }

  // Determine if git clone or git pull is needed
  const gitRepoPath = path.join(projectExecDir, ".git")
  if (!fs.existsSync(gitRepoPath)) {
    console.log(`Repository not found in ${projectExecDir}. Cloning...`)
    // For cloning, we need to execute in the parent directory of projectExecDir
    // and clone into the basename of projectExecDir
    const parentDir = path.dirname(projectExecDir)
    const repoName = path.basename(projectExecDir)
    commandsToExecute.unshift(`git clone ${project.repo} ${repoName}`)
    // Set the CWD for the clone command to the parent directory
    // Subsequent commands will run in projectExecDir
    logEntry.output.push({ command: `git clone ${project.repo} ${repoName}`, stdout: "", stderr: "", error: null })
    console.log(`🚀 Webhook received for ${project.name}. Running initial clone and commands...`)
  } else {
    console.log(`Repository found in ${projectExecDir}. Pulling latest changes...`)
    commandsToExecute.unshift("git pull")
    logEntry.output.push({ command: `git pull`, stdout: "", stderr: "", error: null })
    console.log(`🚀 Webhook received for ${project.name}. Running pull and commands...`)
  }

  let commandIndex = 0
  const executeNextCommand = () => {
    if (commandIndex < commandsToExecute.length) {
      const cmd = commandsToExecute[commandIndex]
      // For the initial git clone, the cwd needs to be the parent directory
      // For all other commands (including git pull), the cwd is projectExecDir
      const currentCwd =
        commandIndex === 0 && cmd.startsWith("git clone") ? path.dirname(projectExecDir) : projectExecDir

      console.log(`⚙️ Running: ${cmd} in ${currentCwd}`)
      const child = exec(cmd, { cwd: currentCwd }, (err, stdout, stderr) => {
        const currentLogIndex = logs.findIndex((log) => log.time === logEntry.time)
        if (currentLogIndex !== -1) {
          logs[currentLogIndex].output.push({ command: cmd, stdout, stderr, error: err ? err.message : null })
          if (err) {
            console.error(`❌ ${cmd}:`, stderr)
            logs[currentLogIndex].status = "failed"
          } else {
            console.log(`✅ ${cmd}:`, stdout)
          }
          save(LOGS_FILE, logs)
        }
        commandIndex++
        executeNextCommand() // Execute next command
      })

      child.stdout.on("data", (data) => {
        console.log(`[${cmd} stdout]: ${data.toString()}`)
      })
      child.stderr.on("data", (data) => {
        console.error(`[${cmd} stderr]: ${data.toString()}`)
      })
    } else {
      const currentLogIndex = logs.findIndex((log) => log.time === logEntry.time)
      if (currentLogIndex !== -1 && logs[currentLogIndex].status !== "failed") {
        logs[currentLogIndex].status = "completed"
        save(LOGS_FILE, logs)
      }
      console.log(`🎉 All commands for ${project.name} executed.`)
    }
  }

  executeNextCommand() // Start executing commands

  res.send("OK")
})

app.listen(PORT, () => console.log(`✅ CI/CD Server running at http://localhost:${PORT}`))
