import { test } from "node:test";
import assert from "node:assert";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  symlinkSync,
  rmSync,
  realpathSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PathValidator } from "../lib/path-validator.js";

const workDir = process.cwd();
const validator = new PathValidator(workDir);

function withTempDir(fn) {
  const raw = mkdtempSync(join(tmpdir(), "leash-test-"));
  const dir = realpathSync(raw);
  try {
    fn(dir);
  } finally {
    rmSync(raw, { recursive: true, force: true });
  }
}

// isWithinAllowedDir
test("allows relative path inside working dir", () => {
  assert.strictEqual(validator.isWithinAllowedDir("./src/file.ts"), true);
});

test("allows nested relative path", () => {
  assert.strictEqual(validator.isWithinAllowedDir("src/lib/util.ts"), true);
});

test("blocks path with ..", () => {
  assert.strictEqual(validator.isWithinAllowedDir("../outside"), false);
});

test("blocks home directory path", () => {
  assert.strictEqual(validator.isWithinAllowedDir("~/Documents"), false);
});

test("blocks $HOME expansion", () => {
  assert.strictEqual(validator.isWithinAllowedDir("$HOME/file"), false);
});

test("blocks ${HOME} expansion", () => {
  assert.strictEqual(validator.isWithinAllowedDir("${HOME}/file"), false);
});

test("blocks absolute path outside", () => {
  assert.strictEqual(validator.isWithinAllowedDir("/etc/passwd"), false);
});

test("allows working directory root path", () => {
  assert.strictEqual(validator.isWithinAllowedDir("."), true);
  assert.strictEqual(validator.isWithinAllowedDir("./"), true);
});

test("allows $PWD expansion", () => {
  assert.strictEqual(validator.isWithinAllowedDir("$PWD/file"), true);
  assert.strictEqual(validator.isWithinAllowedDir("${PWD}/file"), true);
});

// isSafeForWrite
test("allows /dev/null for write", () => {
  assert.strictEqual(validator.isSafeForWrite("/dev/null"), true);
});

test("allows /tmp for write", () => {
  assert.strictEqual(validator.isSafeForWrite("/tmp/cache"), true);
});

test("blocks home path for write", () => {
  assert.strictEqual(validator.isSafeForWrite("~/file"), false);
});

// isTempPath
test("recognizes /tmp as temp", () => {
  assert.strictEqual(validator.isTempPath("/tmp/file"), true);
});

test("recognizes /var/tmp as temp", () => {
  assert.strictEqual(validator.isTempPath("/var/tmp/file"), true);
});

test("/dev/null is not temp path", () => {
  assert.strictEqual(validator.isTempPath("/dev/null"), false);
});

// isPlatformPath
test("recognizes ~/.claude as platform path", () => {
  assert.strictEqual(validator.isPlatformPath("~/.claude/plans/test.md"), true);
});

test("recognizes ~/.factory as platform path", () => {
  assert.strictEqual(validator.isPlatformPath("~/.factory/settings.json"), true);
});

test("recognizes ~/.pi as platform path", () => {
  assert.strictEqual(validator.isPlatformPath("~/.pi/agent/test.md"), true);
});

test("recognizes ~/.config/opencode as platform path", () => {
  assert.strictEqual(validator.isPlatformPath("~/.config/opencode/config.json"), true);
});

test("does not recognize arbitrary home paths as platform path", () => {
  assert.strictEqual(validator.isPlatformPath("~/Documents/file.txt"), false);
});

// isProtectedPath
test("protects .env", () => {
  const result = validator.isProtectedPath(".env");
  assert.strictEqual(result.protected, true);
  assert.strictEqual(result.name, ".env files");
});

test("protects .env.local", () => {
  const result = validator.isProtectedPath(".env.local");
  assert.strictEqual(result.protected, true);
});

test("protects .env.production", () => {
  const result = validator.isProtectedPath(".env.production");
  assert.strictEqual(result.protected, true);
});

test("allows .env.example", () => {
  const result = validator.isProtectedPath(".env.example");
  assert.strictEqual(result.protected, false);
});

test("protects .git", () => {
  const result = validator.isProtectedPath(".git");
  assert.strictEqual(result.protected, true);
  assert.strictEqual(result.name, ".git directory");
});

test("protects .git/config", () => {
  const result = validator.isProtectedPath(".git/config");
  assert.strictEqual(result.protected, true);
});

test("protects .git/hooks/pre-commit", () => {
  const result = validator.isProtectedPath(".git/hooks/pre-commit");
  assert.strictEqual(result.protected, true);
});

test("protects .leashrc", () => {
  const result = validator.isProtectedPath(".leashrc");
  assert.strictEqual(result.protected, true);
  assert.strictEqual(result.name, ".leashrc config");
});

test("does not protect paths outside working dir", () => {
  const result = validator.isProtectedPath("/etc/.env");
  assert.strictEqual(result.protected, false);
});

// Symlink escape - critical security test
test("blocks symlink that points outside working dir", () => {
  const tempDir = mkdtempSync(join(tmpdir(), "leash-test-"));
  const symlinkPath = join(workDir, "test-escape-link");

  try {
    symlinkSync(tempDir, symlinkPath);
    assert.strictEqual(validator.isWithinAllowedDir(symlinkPath), false);
    assert.strictEqual(validator.isWithinAllowedDir("./test-escape-link"), false);
  } finally {
    rmSync(symlinkPath, { force: true });
    rmSync(tempDir, { force: true, recursive: true });
  }
});

// Allowed directories
test("allows path inside an allowed directory", () => {
  withTempDir((allowedDir) => {
    const v = new PathValidator(workDir, [allowedDir]);
    assert.strictEqual(v.isWithinAllowedDir(join(allowedDir, "file.ts")), true);
  });
});

test("blocks path outside both working dir and allowed dirs", () => {
  withTempDir((allowedDir) => {
    const v = new PathValidator(workDir, [allowedDir]);
    assert.strictEqual(v.isWithinAllowedDir("/etc/passwd"), false);
  });
});

test("protects .env inside allowed directory", () => {
  withTempDir((allowedDir) => {
    const v = new PathValidator(workDir, [allowedDir]);
    const result = v.isProtectedPath(join(allowedDir, ".env"));
    assert.strictEqual(result.protected, true);
    assert.strictEqual(result.name, ".env files");
  });
});

test("protects .git/config inside allowed directory", () => {
  withTempDir((allowedDir) => {
    const v = new PathValidator(workDir, [allowedDir]);
    const result = v.isProtectedPath(join(allowedDir, ".git/config"));
    assert.strictEqual(result.protected, true);
    assert.strictEqual(result.name, ".git directory");
  });
});

test("protects .leashrc inside allowed directory", () => {
  withTempDir((allowedDir) => {
    const v = new PathValidator(workDir, [allowedDir]);
    const result = v.isProtectedPath(join(allowedDir, ".leashrc"));
    assert.strictEqual(result.protected, true);
    assert.strictEqual(result.name, ".leashrc config");
  });
});

test("multiple allowed directories all work", () => {
  const raw1 = mkdtempSync(join(tmpdir(), "leash-allowed-1-"));
  const raw2 = mkdtempSync(join(tmpdir(), "leash-allowed-2-"));
  const dir1 = realpathSync(raw1);
  const dir2 = realpathSync(raw2);
  try {
    const v = new PathValidator(workDir, [dir1, dir2]);
    assert.strictEqual(v.isWithinAllowedDir(join(dir1, "a.ts")), true);
    assert.strictEqual(v.isWithinAllowedDir(join(dir2, "b.ts")), true);
  } finally {
    rmSync(raw1, { recursive: true, force: true });
    rmSync(raw2, { recursive: true, force: true });
  }
});

test("skips allowed directory that no longer exists", () => {
  const v = new PathValidator(workDir, ["/nonexistent/dir"]);
  assert.strictEqual(v.isWithinAllowedDir("/nonexistent/dir/file.ts"), false);
});

// suggestAllowableSymlink

test("suggests symlink name when blocked path is under a top-level symlink target", () => {
  withTempDir((hubDir) => {
    withTempDir((targetDir) => {
      const linkPath = join(hubDir, "proj-a");
      symlinkSync(targetDir, linkPath);
      const v = new PathValidator(hubDir);
      const result = v.suggestAllowableSymlink(join(targetDir, "src/file.ts"));
      assert.strictEqual(result, "proj-a");
    });
  });
});

test("returns null for non-symlink entries", () => {
  withTempDir((hubDir) => {
    const subDir = join(hubDir, "real-dir");
    mkdirSync(subDir);
    writeFileSync(join(subDir, "file.ts"), "");
    const v = new PathValidator(hubDir);
    const result = v.suggestAllowableSymlink("/some/other/path/file.ts");
    assert.strictEqual(result, null);
  });
});

test("returns null when path is not under any symlink target", () => {
  withTempDir((hubDir) => {
    withTempDir((targetDir) => {
      const linkPath = join(hubDir, "proj-a");
      symlinkSync(targetDir, linkPath);
      const v = new PathValidator(hubDir);
      const result = v.suggestAllowableSymlink("/completely/different/path");
      assert.strictEqual(result, null);
    });
  });
});
