import { test } from "node:test";
import assert from "node:assert";
import {
  mkdtempSync,
  writeFileSync,
  symlinkSync,
  rmSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parseLeashrc, readLeashrc } from "../lib/leashrc.js";

function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "leashrc-test-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// parseLeashrc

test("empty string returns empty allow list", () => {
  const result = parseLeashrc("");
  assert.deepStrictEqual(result, { allow: [] });
});

test("parses allow section with multiple paths", () => {
  const content = `[allow]
/Users/test/project-a
/Users/test/project-b`;
  const result = parseLeashrc(content);
  assert.deepStrictEqual(result.allow, [
    "/Users/test/project-a",
    "/Users/test/project-b",
  ]);
});

test("ignores comments", () => {
  const content = `[allow]
# this is a comment
/Users/test/project-a
# another comment
/Users/test/project-b`;
  const result = parseLeashrc(content);
  assert.deepStrictEqual(result.allow, [
    "/Users/test/project-a",
    "/Users/test/project-b",
  ]);
});

test("ignores blank lines", () => {
  const content = `[allow]

/Users/test/project-a

/Users/test/project-b
`;
  const result = parseLeashrc(content);
  assert.deepStrictEqual(result.allow, [
    "/Users/test/project-a",
    "/Users/test/project-b",
  ]);
});

test("ignores lines before any section", () => {
  const content = `some random line
/stray/path
[allow]
/Users/test/project-a`;
  const result = parseLeashrc(content);
  assert.deepStrictEqual(result.allow, ["/Users/test/project-a"]);
});

test("ignores unknown sections", () => {
  const content = `[deny]
/Users/test/blocked
[allow]
/Users/test/project-a
[other]
/Users/test/other`;
  const result = parseLeashrc(content);
  assert.deepStrictEqual(result.allow, ["/Users/test/project-a"]);
});

test("trims whitespace from paths", () => {
  const content = `[allow]
  /Users/test/project-a
\t/Users/test/project-b\t`;
  const result = parseLeashrc(content);
  assert.deepStrictEqual(result.allow, [
    "/Users/test/project-a",
    "/Users/test/project-b",
  ]);
});

// readLeashrc

test("missing file returns empty allow list", () => {
  const result = readLeashrc("/nonexistent/path");
  assert.deepStrictEqual(result, { allow: [] });
});

test("reads and parses .leashrc from directory", () => {
  withTempDir((dir) => {
    writeFileSync(
      join(dir, ".leashrc"),
      `[allow]\n/Users/test/project-a\n`
    );
    const result = readLeashrc(dir);
    assert.deepStrictEqual(result.allow, ["/Users/test/project-a"]);
  });
});

test("symlink .leashrc returns empty allow list", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, "real-file"), "[allow]\n/Users/test/evil\n");
    symlinkSync(join(dir, "real-file"), join(dir, ".leashrc"));
    const result = readLeashrc(dir);
    assert.deepStrictEqual(result, { allow: [] });
  });
});

test("empty .leashrc file returns empty allow list", () => {
  withTempDir((dir) => {
    writeFileSync(join(dir, ".leashrc"), "");
    const result = readLeashrc(dir);
    assert.deepStrictEqual(result, { allow: [] });
  });
});
