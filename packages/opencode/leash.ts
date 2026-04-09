import type { Plugin } from "@opencode-ai/plugin";
import { CommandAnalyzer, checkForUpdates, readLeashrc } from "../core/index.js";

export const Leash: Plugin = async ({ directory, client }) => {
  return {
    event: async ({ event }) => {
      if (event.type === "session.created") {
        await client.tui.showToast({
          body: { message: "🔒 Leash active", variant: "info" },
        });

        const update = await checkForUpdates();
        if (update.hasUpdate) {
          await client.tui.showToast({
            body: {
              message: `🔄 Leash ${update.latestVersion} available.\nRun: leash update (restart required)`,
              variant: "warning",
            },
          });
        }
      }
    },

    "tool.execute.before": async (input, output) => {
      const { allow } = readLeashrc(directory);
      const analyzer = new CommandAnalyzer(directory, allow);

      // Shell command execution
      const shellTools = ["execute", "bash", "shell"];
      if (shellTools.includes(input.tool)) {
        const command = output.args?.command || output.args?.script || "";
        const result = analyzer.analyze(command);

        if (result.blocked) {
          throw new Error(
            `Command blocked: ${command}\n` +
              `Reason: ${result.reason}\n` +
              `Working directory: ${directory}\n` +
              `Action: Guide the user to run the command manually.`
          );
        }
      }

      // File write/edit/patch operations
      const fileTools = ["write", "edit", "patch"];
      if (fileTools.includes(input.tool)) {
        const path = output.args?.path || "";
        const result = analyzer.validatePath(path);

        if (result.blocked) {
          const suggestion = analyzer.suggestAllow(path);
          let msg =
            `File operation blocked: ${path}\n` +
            `Reason: ${result.reason}\n` +
            `Working directory: ${directory}\n`;

          if (suggestion) {
            msg +=
              `Hint: This path is reachable via symlink "${suggestion}" in your working directory.\n` +
              `      Run: leash allow ${suggestion}\n`;
          }

          msg += `Action: Guide the user to perform this operation manually.`;
          throw new Error(msg);
        }
      }
    },
  };
};

export default Leash;
