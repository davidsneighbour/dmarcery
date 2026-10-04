import { homedir } from "node:os";
import { join } from "node:path";

export interface DataPaths {
  dataDir: string;
  database: string;
  archive: string;
}

/**
 * Resolves the data directory. Order: explicit option, DMARC_HOME,
 * $XDG_DATA_HOME/dmarc, ~/.local/share/dmarc.
 */
export function resolvePaths(dataDir?: string): DataPaths {
  const env = process.env;
  const dir =
    dataDir ??
    (env["DMARC_HOME"] || undefined) ??
    join(env["XDG_DATA_HOME"] || join(homedir(), ".local", "share"), "dmarc");
  return {
    dataDir: dir,
    database: join(dir, "dmarc.sqlite"),
    archive: join(dir, "reports"),
  };
}

/** Makes a value safe as a single path component. */
export function safeComponent(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9._@+-]+/g, "_").replace(/^\.+/, "_");
  return (cleaned || "_").slice(0, 120);
}
