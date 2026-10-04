import { existsSync, readdirSync, renameSync, rmSync } from "node:fs";
import { join, relative } from "node:path";
import { Database } from "./db.ts";
import { importFile } from "./importer.ts";
import type { DataPaths } from "./paths.ts";

export interface RebuildResult {
  files: number;
  imported: number;
  duplicates: number;
  failed: { file: string; error: string }[];
  senders: number;
  backup: string | null;
}

function archiveFiles(directory: string): string[] {
  if (!existsSync(directory)) {
    return [];
  }
  return readdirSync(directory, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith(".xml"))
    .map((entry) => join(entry.parentPath, entry.name))
    .sort();
}

/**
 * Creates a fresh database from the XML archive (PLAN.md rule 7).
 * Configured data (the sender registry) is not in the archive, so it is copied
 * from the current database. The previous database is kept as dmarc.sqlite.bak.
 */
export function rebuild(paths: DataPaths): RebuildResult {
  const target = `${paths.database}.rebuild`;
  rmSync(target, { force: true });
  const fresh = new Database(target);
  const result: RebuildResult = { files: 0, imported: 0, duplicates: 0, failed: [], senders: 0, backup: null };

  try {
    const old = existsSync(paths.database) ? new Database(paths.database) : null;
    const previousImports = new Map<string, { sourceFile: string; importedAt: string }>();
    if (old !== null) {
      fresh.transaction(() => {
        for (const row of old.all("SELECT id, name, status, notes, created_at, updated_at FROM senders")) {
          fresh.run(
            `INSERT INTO senders (id, name, status, notes, created_at, updated_at)
             VALUES (:id, :name, :status, :notes, :created_at, :updated_at)`,
            row,
          );
          result.senders += 1;
        }
        for (const row of old.all(
          "SELECT id, sender_id, identifier_type, identifier_value, range_start, range_end, created_at FROM sender_identifiers",
        )) {
          fresh.run(
            `INSERT INTO sender_identifiers (id, sender_id, identifier_type, identifier_value, range_start, range_end, created_at)
             VALUES (:id, :sender_id, :identifier_type, :identifier_value, :range_start, :range_end, :created_at)`,
            row,
          );
        }
      });
      for (const row of old.all("SELECT source_sha256, source_file, imported_at FROM reports")) {
        previousImports.set(String(row["source_sha256"]), {
          sourceFile: String(row["source_file"]),
          importedAt: String(row["imported_at"]),
        });
      }
      old.close();
    }

    for (const file of archiveFiles(paths.archive)) {
      result.files += 1;
      try {
        const imported = importFile(fresh, file, {
          archiveDir: paths.archive,
          dataDir: paths.dataDir,
          archivedAs: relative(paths.dataDir, file),
          analyse: false,
        });
        for (const report of imported) {
          if (report.status === "imported") {
            result.imported += 1;
          } else {
            result.duplicates += 1;
          }
        }
      } catch (error) {
        result.failed.push({ file, error: error instanceof Error ? error.message : String(error) });
      }
    }

    // Keep the original file names and import times where the previous database knew them.
    fresh.transaction(() => {
      for (const [sha, previous] of previousImports) {
        fresh.run("UPDATE reports SET source_file = :file, imported_at = :at WHERE source_sha256 = :sha", {
          file: previous.sourceFile,
          at: previous.importedAt,
          sha,
        });
      }
    });
  } catch (error) {
    fresh.close();
    rmSync(target, { force: true });
    throw error;
  }

  fresh.close();
  if (existsSync(paths.database)) {
    result.backup = `${paths.database}.bak`;
    renameSync(paths.database, result.backup);
  }
  renameSync(target, paths.database);
  return result;
}
