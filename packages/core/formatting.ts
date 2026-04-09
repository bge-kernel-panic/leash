import type { CommandAnalyzer } from "./command-analyzer.js";

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

export function formatBlockMessage(
  label: string,
  detail: string,
  reason: string,
  cwd: string,
  analyzer: CommandAnalyzer,
  path?: string
): string {
  let msg =
    `🚫 ${label}: ${detail}\n` +
    `Reason: ${reason}\n` +
    `Working directory: ${cwd}\n`;

  if (path) {
    const suggestion = analyzer.suggestAllow(path);
    if (suggestion) {
      msg +=
        `Hint: This path is reachable via symlink "${suggestion}" in your working directory.\n` +
        `      Run: leash allow ${suggestion}\n`;
    }
  }

  msg += `Action: Guide the user to perform this operation manually.`;
  return msg;
}
