import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { crc32, gunzipSync, inflateRawSync } from "node:zlib";
import { ReportError } from "./parse.ts";

/**
 * Reports arrive as plain XML, gzip (.xml.gz), or zip (.zip) files.
 * The format is detected from the content, not the file name.
 *
 * Anyone can send a "report" to a rua address, so decompression is limited:
 * zlib's maxOutputLength stops at the real output size, not the declared one.
 */
export const MAX_REPORT_BYTES = 64 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 1000;

export interface ReportSource {
  /** Display name, for example `report.zip:report.xml`. */
  name: string;
  /** Stored in reports.source_file. */
  sourceFile: string;
  /** The XML bytes. */
  data: Buffer;
}

export type ContainerFormat = "xml" | "gzip" | "zip";

export function detectFormat(data: Buffer): ContainerFormat {
  if (data[0] === 0x1f && data[1] === 0x8b) {
    return "gzip";
  }
  if (data[0] === 0x50 && data[1] === 0x4b && (data[2] === 0x03 || data[2] === 0x05) && (data[3] === 0x04 || data[3] === 0x06)) {
    return "zip";
  }
  return "xml";
}

function gunzip(data: Buffer, name: string): Buffer {
  try {
    return gunzipSync(data, { maxOutputLength: MAX_REPORT_BYTES });
  } catch (error) {
    const reason = error instanceof RangeError ? `larger than ${MAX_REPORT_BYTES} bytes` : "corrupt gzip data";
    throw new ReportError(`Cannot decompress ${name}: ${reason}`);
  }
}

interface ZipEntry {
  name: string;
  data: Buffer;
}

/** Reads the members of a zip file (stored or deflated, no zip64, no encryption). */
export function unzip(data: Buffer, name: string): ZipEntry[] {
  const fail = (reason: string): never => {
    throw new ReportError(`Cannot read zip ${name}: ${reason}`);
  };

  // End of central directory: 22 bytes plus a comment of up to 65535 bytes.
  let eocd = -1;
  for (let offset = data.length - 22; offset >= Math.max(0, data.length - 22 - 0xffff); offset -= 1) {
    if (data.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  if (eocd < 0) fail("no central directory");
  const entryCount = data.readUInt16LE(eocd + 10);
  let offset = data.readUInt32LE(eocd + 16);
  if (entryCount === 0xffff || offset === 0xffffffff) fail("zip64 is not supported");
  if (entryCount > MAX_ZIP_ENTRIES) fail(`more than ${MAX_ZIP_ENTRIES} entries`);

  const entries: ZipEntry[] = [];
  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > data.length || data.readUInt32LE(offset) !== 0x02014b50) fail("corrupt central directory");
    const flags = data.readUInt16LE(offset + 8);
    const method = data.readUInt16LE(offset + 10);
    const crc = data.readUInt32LE(offset + 16);
    const compressedSize = data.readUInt32LE(offset + 20);
    const size = data.readUInt32LE(offset + 24);
    const nameLength = data.readUInt16LE(offset + 28);
    const extraLength = data.readUInt16LE(offset + 30);
    const commentLength = data.readUInt16LE(offset + 32);
    const localOffset = data.readUInt32LE(offset + 42);
    const entryName = data.toString(flags & 0x0800 ? "utf8" : "latin1", offset + 46, offset + 46 + nameLength);
    offset += 46 + nameLength + extraLength + commentLength;

    if (entryName.endsWith("/")) continue;
    if (flags & 0x0001) fail(`${entryName} is encrypted`);
    if (compressedSize === 0xffffffff || size === 0xffffffff) fail("zip64 is not supported");
    if (size > MAX_REPORT_BYTES) fail(`${entryName} is larger than ${MAX_REPORT_BYTES} bytes`);

    if (localOffset + 30 > data.length || data.readUInt32LE(localOffset) !== 0x04034b50) fail(`corrupt local header for ${entryName}`);
    const start = localOffset + 30 + data.readUInt16LE(localOffset + 26) + data.readUInt16LE(localOffset + 28);
    if (start + compressedSize > data.length) fail(`${entryName} is truncated`);
    const raw = data.subarray(start, start + compressedSize);

    let content: Buffer;
    if (method === 0) {
      content = Buffer.from(raw);
    } else if (method === 8) {
      try {
        content = inflateRawSync(raw, { maxOutputLength: Math.max(size, 1) });
      } catch {
        return fail(`${entryName} cannot be decompressed or is larger than declared`);
      }
    } else {
      return fail(`${entryName} uses unsupported compression method ${method}`);
    }
    if (content.length !== size || crc32(content) !== crc) fail(`${entryName} fails the CRC check`);
    entries.push({ name: entryName, data: content });
  }
  return entries;
}

/** Reads a report file and returns the XML report(s) it contains. */
export function readReportSources(path: string): ReportSource[] {
  const data = readFileSync(path);
  const file = basename(path);
  switch (detectFormat(data)) {
    case "xml":
      return [{ name: path, sourceFile: file, data }];
    case "gzip":
      return [{ name: path, sourceFile: file, data: gunzip(data, file) }];
    case "zip": {
      const members = unzip(data, file).filter((entry) => entry.name.toLowerCase().endsWith(".xml"));
      if (members.length === 0) {
        throw new ReportError(`No .xml report in ${file}`);
      }
      return members.map((entry) => ({
        name: `${path}:${entry.name}`,
        sourceFile: `${file}:${basename(entry.name)}`,
        data: entry.data,
      }));
    }
  }
}

/** File names that collectFiles picks up from directories. */
export function isReportFileName(name: string): boolean {
  return /\.(xml|gz|zip)$/i.test(name);
}
