#!/usr/bin/env node
import { CommandAnalyzer, checkForUpdates, readLeashrc, readStdin, formatBlockMessage } from "../core/index.js";

interface FactoryHookInput {
  hook_event_name: string;
  tool_name?: string;
  tool_input?: {
    command?: string;
    file_path?: string;
  };
  cwd?: string;
}

async function main() {
  let input: FactoryHookInput;

  try {
    const raw = await readStdin();
    input = JSON.parse(raw);
  } catch {
    console.error("Failed to parse input JSON");
    process.exit(1);
  }

  const { hook_event_name, tool_name, tool_input } = input;

  // Get working directory from env var (preferred) or input
  const cwd = process.env.FACTORY_PROJECT_DIR || input.cwd || process.cwd();

  // SessionStart: show activation message and check for updates
  if (hook_event_name === "SessionStart") {
    const messages: string[] = ["🔒 Leash active"];

    const update = await checkForUpdates();
    if (update.hasUpdate) {
      messages.push(
        `🔄 Leash ${update.latestVersion} available. Run: leash update`
      );
    }

    console.log(JSON.stringify({ systemMessage: messages.join("\n") }));
    process.exit(0);
  }

  // PreToolUse: security checks
  const { allow } = readLeashrc(cwd);
  const analyzer = new CommandAnalyzer(cwd, allow);

  // Shell command execution
  if (tool_name === "Execute") {
    const command = tool_input?.command || "";
    const result = analyzer.analyze(command);

    if (result.blocked) {
      console.error(
        formatBlockMessage("Command blocked", command, result.reason!, cwd, analyzer)
      );
      process.exit(2);
    }
  }

  // File write/edit operations
  if (tool_name === "Write" || tool_name === "Edit") {
    const path = tool_input?.file_path || "";
    const result = analyzer.validatePath(path);

    if (result.blocked) {
      console.error(
        formatBlockMessage("File operation blocked", path, result.reason!, cwd, analyzer, path)
      );
      process.exit(2);
    }
  }

  // Allow operation
  process.exit(0);
}

main();
