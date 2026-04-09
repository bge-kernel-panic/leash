import { resolve, relative, join } from "path";
import { homedir } from "os";
import { realpathSync, readdirSync, lstatSync } from "fs";
import {
  SAFE_WRITE_PATHS,
  TEMP_PATHS,
  PLATFORM_PATHS,
  PROTECTED_PATTERNS,
} from "./constants.js";

export class PathValidator {
  constructor(
    private workingDirectory: string,
    private allowedDirectories: string[] = []
  ) {}

  expand(path: string): string {
    return path
      .replace(/^~(?=\/|$)/, homedir())
      .replace(/\$\{?(\w+)\}?/g, (_, name) => {
        if (name === "HOME") return homedir();
        if (name === "PWD") return this.workingDirectory;
        return process.env[name] || "";
      });
  }

  private resolveReal(path: string): string {
    const expanded = this.expand(path);
    const resolved = resolve(this.workingDirectory, expanded);

    try {
      return realpathSync(resolved);
    } catch {
      // Path doesn't exist yet, use resolved path
      return resolved;
    }
  }

  private isWithinDir(realPath: string, dir: string): boolean {
    try {
      const realDir = realpathSync(dir);

      if (realPath === realDir) {
        return true;
      }

      const rel = relative(realDir, realPath);
      return !!rel && !rel.startsWith("..") && !rel.startsWith("/");
    } catch {
      return false;
    }
  }

  isWithinAllowedDir(path: string): boolean {
    const realPath = this.resolveReal(path);

    if (this.isWithinDir(realPath, this.workingDirectory)) return true;

    for (const dir of this.allowedDirectories) {
      if (this.isWithinDir(realPath, dir)) return true;
    }

    return false;
  }

  private matchesAny(resolved: string, paths: string[]): boolean {
    return paths.some((p) => resolved === p || resolved.startsWith(p + "/"));
  }

  isSafeForWrite(path: string): boolean {
    const resolved = this.resolveReal(path);
    return this.matchesAny(resolved, SAFE_WRITE_PATHS);
  }

  isTempPath(path: string): boolean {
    const resolved = this.resolveReal(path);
    return this.matchesAny(resolved, TEMP_PATHS);
  }

  isPlatformPath(path: string): boolean {
    const resolved = this.resolveReal(path);
    const home = homedir();
    const platformPaths = PLATFORM_PATHS.map((p) => `${home}/${p}`);
    return this.matchesAny(resolved, platformPaths);
  }

  isProtectedPath(path: string): { protected: boolean; name?: string } {
    if (!this.isWithinAllowedDir(path)) {
      return { protected: false };
    }

    const realPath = this.resolveReal(path);
    const dirsToCheck = [this.workingDirectory, ...this.allowedDirectories];

    for (const dir of dirsToCheck) {
      try {
        const realDir = realpathSync(dir);
        const relativePath = relative(realDir, realPath);

        if (
          !relativePath ||
          relativePath.startsWith("..") ||
          relativePath.startsWith("/")
        ) {
          continue;
        }

        for (const { pattern, name } of PROTECTED_PATTERNS) {
          if (pattern.test(relativePath)) {
            return { protected: true, name };
          }
        }
      } catch {
        continue;
      }
    }

    return { protected: false };
  }

  suggestAllowableSymlink(blockedPath: string): string | null {
    try {
      const realPath = this.resolveReal(blockedPath);
      const entries = readdirSync(this.workingDirectory);

      for (const entry of entries) {
        const entryPath = join(this.workingDirectory, entry);
        try {
          if (!lstatSync(entryPath).isSymbolicLink()) continue;
          const target = realpathSync(entryPath);
          if (this.isWithinDir(realPath, target)) return entry;
        } catch {
          continue;
        }
      }
    } catch {
      // workingDirectory unreadable
    }

    return null;
  }
}
