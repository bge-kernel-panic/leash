export const DANGEROUS_COMMANDS = new Set([
  "rm",
  "rmdir",
  "unlink",
  "shred",
  "mv",
  "cp",
  "chmod",
  "chown",
  "chgrp",
  "truncate",
  "dd",
  "ln",
]);

export const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /\bfind\b.*\s-delete\b/, name: "find -delete" },
  { pattern: /\bfind\b.*-exec\s+(rm|mv|cp)\b/, name: "find -exec" },
  { pattern: /\bxargs\s+(-[^\s]+\s+)*(rm|mv|cp)\b/, name: "xargs" },
  { pattern: /\brsync\b.*--delete\b/, name: "rsync --delete" },
];

export const REDIRECT_PATTERN =
  />{1,2}\s*(?:"([^"]+)"|'([^']+)'|([^\s;|&>]+))/g;

const DEVICE_PATHS = ["/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr"];

export const PLATFORM_PATHS = [
  ".claude",
  ".factory",
  ".pi",
  ".config/opencode",
];

export const TEMP_PATHS = [
  "/tmp",
  "/var/tmp",
  "/private/tmp",
  "/private/var/tmp",
];

export const SAFE_WRITE_PATHS = [...DEVICE_PATHS, ...TEMP_PATHS];

/** Protected paths within working directory - blocks write and delete operations */
export const PROTECTED_PATTERNS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /^\.env($|\.(?!example$).+)/, name: ".env files" },
  { pattern: /^\.git(\/|$)/, name: ".git directory" },
];

/** Blocked even within working directory - unconditionally dangerous commands */
export const ALWAYS_BLOCKED_PATTERNS: Array<{ pattern: RegExp; name: string }> =
  [
    // Git — can destroy uncommitted work or remote history
    { pattern: /\bgit\s+checkout\b.*\s--\s/, name: "git checkout --" },
    { pattern: /\bgit\s+restore\s+(?!--staged)/, name: "git restore" },
    { pattern: /\bgit\s+reset\s+.*--hard\b/, name: "git reset --hard" },
    { pattern: /\bgit\s+reset\s+.*--merge\b/, name: "git reset --merge" },
    {
      pattern: /\bgit\s+clean\s+.*(-[a-zA-Z]*f[a-zA-Z]*|--force)\b/,
      name: "git clean --force",
    },
    { pattern: /\bgit\s+push\s+.*(-f|--force)\b/, name: "git push --force" },
    { pattern: /\bgit\s+branch\s+.*-D\b/, name: "git branch -D" },
    { pattern: /\bgit\s+stash\s+drop\b/, name: "git stash drop" },
    { pattern: /\bgit\s+stash\s+clear\b/, name: "git stash clear" },

    // System — always dangerous regardless of path
    { pattern: /\bmkfs(\.\w+)?\s+\/dev\//, name: "mkfs" },
    {
      pattern: /(\w+|:)\(\)\s*\{[^}]*\1\s*\|\s*\1[^}]*&/,
      name: "fork bomb (recursive)",
    },
    {
      pattern: /while\s+(true|:|1)\b.*\bdo\b.*;?\s*\b(bash|sh|zsh)\b.*&.*\bdone\b/,
      name: "fork bomb (loop)",
    },
    { pattern: /\b(curl|wget)\b.+\|\s*(ba)?sh\b/, name: "pipe to shell" },
    { pattern: /\beval\b.+\$\(.*(curl|wget)\b/, name: "eval remote code" },
    {
      pattern: /\bdocker\s+volume\s+(rm|prune)\b/,
      name: "docker volume rm/prune",
    },
    { pattern: /\bcrontab\s+-r\b/, name: "crontab -r" },
    { pattern: /\bchmod\b.*\b777\b/, name: "chmod 777" },
  ];
