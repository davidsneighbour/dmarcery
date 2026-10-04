const numberFormat = new Intl.NumberFormat("en-GB");

export function formatNumber(value: number): string {
  return numberFormat.format(value);
}

export function formatDateTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString().slice(0, 16).replace("T", " ");
}

export interface Column {
  header: string;
  key: string;
  align?: "left" | "right";
  /** Optional value transformation for display. */
  format?: (value: unknown) => string;
}

function display(value: unknown): string {
  if (value === null || value === undefined) {
    return "-";
  }
  if (typeof value === "number" || typeof value === "bigint") {
    return formatNumber(Number(value));
  }
  return String(value);
}

/** Renders rows as an aligned plain-text table. The last column is never padded. */
export function table(columns: Column[], rows: Record<string, unknown>[]): string {
  const cells = rows.map((row) => columns.map((column) => (column.format ?? display)(row[column.key])));
  const widths = columns.map((column, index) =>
    Math.max(column.header.length, ...cells.map((line) => line[index]?.length ?? 0)),
  );
  const render = (line: string[]): string =>
    line
      .map((cell, index) => {
        const column = columns[index];
        const width = widths[index] ?? 0;
        if (column?.align === "right") {
          return cell.padStart(width);
        }
        return index === line.length - 1 ? cell : cell.padEnd(width);
      })
      .join("   ")
      .trimEnd();
  return [render(columns.map((column) => column.header)), ...cells.map(render)].join("\n");
}

/** Renders label/value pairs with aligned values. */
export function pairs(entries: [string, string][]): string {
  const width = Math.max(...entries.map(([label]) => label.length)) + 1;
  return entries.map(([label, value]) => `${`${label}:`.padEnd(width + 1)}${value}`).join("\n");
}
