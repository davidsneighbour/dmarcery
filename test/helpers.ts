import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32, deflateRawSync } from "node:zlib";
import { type DataPaths, resolvePaths } from "../src/paths.ts";

interface FixtureRecord {
  ip: string;
  count: number;
}

/** Synthetic report with the same structure as real Google reports. Example data only. */
function passingReport(
  reportId: string,
  begin: number,
  records: FixtureRecord[],
): string {
  const rows = records
    .map(
      (record) => `  <record>
    <row>
      <source_ip>${record.ip}</source_ip>
      <count>${record.count}</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>mail.example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>mail.example.com</domain><result>pass</result><selector>resend</selector></dkim>
      <dkim><domain>esp.example</domain><result>pass</result><selector>s1example</selector></dkim>
      <spf><domain>bounce.mail.example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>`,
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>receiver.example</org_name>
    <email>dmarc@receiver.example</email>
    <report_id>${reportId}</report_id>
    <date_range><begin>${begin}</begin><end>${begin + 86_399}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim><aspf>r</aspf><p>reject</p><sp>reject</sp><pct>100</pct><np>reject</np>
  </policy_published>
${rows}
</feedback>
`;
}

const PASSING_REPORTS: [string, number, FixtureRecord[]][] = [
  ["11111111111111111111", 1790640000, [{ ip: "192.0.2.52", count: 1 }]],
  ["12172077135528107070", 1790812800, [{ ip: "192.0.2.55", count: 2 }]],
  [
    "13333333333333333333",
    1790899200,
    [
      { ip: "192.0.2.52", count: 1 },
      { ip: "192.0.2.58", count: 1 },
    ],
  ],
  ["14444444444444444444", 1790985600, [{ ip: "192.0.2.55", count: 1 }]],
];

let samples: string[] | undefined;

/** Writes the four passing fixture reports once and returns their paths. */
export function sampleFiles(): string[] {
  if (samples === undefined) {
    const directory = mkdtempSync(join(tmpdir(), "dmarcery-samples-"));
    samples = PASSING_REPORTS.map(([reportId, begin, records]) =>
      writeFixture(
        directory,
        `receiver.example!example.com!${begin}!${begin + 86_399}.xml`,
        passingReport(reportId, begin, records),
      ),
    );
  }
  return samples;
}

export function temporaryPaths(): DataPaths {
  return resolvePaths(mkdtempSync(join(tmpdir(), "dmarcery-test-")));
}

/** Synthetic report: one aligned Resend record and one spoofed, rejected record. Not real data. */
export const SPOOF_REPORT = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <report_metadata>
    <org_name>example-receiver.test</org_name>
    <email>dmarc@example-receiver.test</email>
    <report_id>test-spoof-0001</report_id>
    <date_range><begin>1791072000</begin><end>1791158399</end></date_range>
    <error>Example error text</error>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim><aspf>r</aspf><p>reject</p><sp>reject</sp><pct>100</pct><fo>1</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.52</source_ip>
      <count>79</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>mail.example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>mail.example.com</domain><selector>resend</selector><result>pass</result></dkim>
      <spf><domain>bounce.mail.example.com</domain><scope>mfrom</scope><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>2001:db8::17</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>reject</disposition><dkim>fail</dkim><spf>fail</spf>
        <reason><type>local_policy</type><comment>first</comment></reason>
        <reason><type>other</type></reason>
      </policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from><envelope_from>spoof.test</envelope_from></identifiers>
    <auth_results>
      <dkim><domain>mail.example.com</domain><selector>resend</selector><result>fail</result><human_result>bad signature</human_result></dkim>
      <spf><domain>spoof.test</domain><result>softfail</result></spf>
    </auth_results>
  </record>
</feedback>
`;

export function writeFixture(
  directory: string,
  name: string,
  content: string | Buffer,
): string {
  const path = join(directory, name);
  writeFileSync(path, content);
  return path;
}

export interface ZipMember {
  name: string;
  content: Buffer;
  /** Overrides the declared uncompressed size, to simulate a lying archive. */
  declaredSize?: number;
}

/** Builds a minimal zip file with deflated members. */
export function buildZip(members: ZipMember[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const member of members) {
    const name = Buffer.from(member.name, "utf8");
    const compressed = deflateRawSync(member.content);
    const crc = crc32(member.content);
    const size = member.declaredSize ?? member.content.length;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(size, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, compressed);
    centrals.push(central, name);
    offset += local.length + name.length + compressed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(members.length, 8);
  end.writeUInt16LE(members.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}
