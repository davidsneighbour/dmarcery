import { isIPv4, isIPv6 } from "node:net";

/**
 * IP addresses are compared as fixed-width, 32-character hexadecimal keys.
 * IPv4 addresses are mapped into the IPv6 space (::ffff:a.b.c.d), so IPv4 and
 * IPv6 share one ordering and plain SQL `BETWEEN` can test CIDR membership.
 */

const IPV4_MAPPED_PREFIX = "00000000000000000000ffff";

function ipv4ToHex(ip: string): string {
  return ip
    .split(".")
    .map((octet) => Number.parseInt(octet, 10).toString(16).padStart(2, "0"))
    .join("");
}

function ipv6ToHex(ip: string): string {
  let address = ip.split("%")[0] ?? ip;
  // Embedded IPv4 tail, for example ::ffff:192.0.2.1
  const lastColon = address.lastIndexOf(":");
  const tail = address.slice(lastColon + 1);
  if (tail.includes(".")) {
    const hex = ipv4ToHex(tail);
    address = `${address.slice(0, lastColon + 1)}${hex.slice(0, 4)}:${hex.slice(4)}`;
  }
  const [head = "", rest] = address.split("::");
  const headGroups = head === "" ? [] : head.split(":");
  const restGroups = rest === undefined || rest === "" ? [] : rest.split(":");
  const missing = rest === undefined ? 0 : 8 - headGroups.length - restGroups.length;
  const groups = [...headGroups, ...Array<string>(missing).fill("0"), ...restGroups];
  return groups.map((group) => group.padStart(4, "0")).join("").toLowerCase();
}

/** Returns the 32-character hex key of an IP address, or null if it is not an IP address. */
export function ipKey(ip: string): string | null {
  const value = ip.trim();
  if (isIPv4(value)) {
    return IPV4_MAPPED_PREFIX + ipv4ToHex(value);
  }
  if (isIPv6(value)) {
    return ipv6ToHex(value);
  }
  return null;
}

export interface IpRange {
  start: string;
  end: string;
}

/** Parses `a.b.c.d/n` or `x:y::/n` into an inclusive key range. Returns null if invalid. */
export function cidrRange(cidr: string): IpRange | null {
  const [address = "", prefixText] = cidr.trim().split("/");
  const key = ipKey(address);
  if (key === null) {
    return null;
  }
  const isV4 = isIPv4(address);
  const maxPrefix = isV4 ? 32 : 128;
  const prefix = prefixText === undefined ? maxPrefix : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    return null;
  }
  const bits = BigInt(`0x${key}`);
  const hostBits = BigInt((isV4 ? 32 : 128) - prefix);
  const hostMask = (1n << hostBits) - 1n;
  const start = bits & ~hostMask;
  const end = start | hostMask;
  const toKey = (value: bigint): string => value.toString(16).padStart(32, "0");
  return { start: toKey(start), end: toKey(end) };
}

/** Network that an address belongs to for "new source network" detection: /24 for IPv4, /48 for IPv6. */
export function networkOf(ip: string): string | null {
  if (isIPv4(ip)) {
    const octets = ip.split(".");
    return `${octets.slice(0, 3).join(".")}.0/24`;
  }
  const key = ipKey(ip);
  if (key === null) {
    return null;
  }
  const groups = key.slice(0, 12).match(/.{4}/g) ?? [];
  return `${groups.map((group) => group.replace(/^0+(?=.)/, "")).join(":")}::/48`;
}
