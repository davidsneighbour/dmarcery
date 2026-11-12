import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { getDomain } from "tldts";

export type AlignmentResult = "pass" | "fail" | "unknown";
export interface AuthObservation {
  domain: string | null;
  result: string | null;
  scope?: string | null;
}
export interface AlignmentCheck {
  result: AlignmentResult;
  note: string | null;
}

function normaliseDomain(value: string | null): string | null {
  if (!value || /[/\\@:?#\s%[\]]/.test(value)) return null;
  const ascii = domainToASCII(value.replace(/\.$/, "")).toLowerCase();
  if (
    !ascii ||
    ascii.length > 253 ||
    isIP(ascii) ||
    !ascii
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  )
    return null;
  return ascii;
}

/** Offline RFC 7489 comparison using the pinned PSL, including private suffixes. */
export function domainsAlign(
  authenticated: string | null,
  headerFrom: string | null,
  mode: string | null,
): boolean | null {
  if (mode !== null && mode !== "r" && mode !== "s") return null;
  const auth = normaliseDomain(authenticated);
  const header = normaliseDomain(headerFrom);
  if (!auth || !header) return null;
  if (mode === "s") return auth === header;
  const options = { allowPrivateDomains: true, extractHostname: false };
  const authOrg = getDomain(auth, options);
  const headerOrg = getDomain(header, options);
  // Public suffixes alone cannot supply an organisational domain.
  return authOrg !== null && headerOrg !== null && authOrg === headerOrg;
}

export function checkMechanism(
  headerFrom: string | null,
  mode: string | null,
  observations: AuthObservation[],
  mechanism: "dkim" | "spf",
): AlignmentCheck {
  const unknown = (note: string): AlignmentCheck => ({
    result: "unknown",
    note,
  });
  if (!normaliseDomain(headerFrom))
    return unknown("Missing or invalid header-from domain");
  if (mode !== null && mode !== "r" && mode !== "s")
    return unknown("Unrecognised alignment mode");
  // Older reports omit scope. Treat those results as MAIL FROM, and expose this assumption.
  const eligible =
    mechanism === "spf"
      ? observations.filter(
          (entry) =>
            entry.scope === null ||
            entry.scope === undefined ||
            entry.scope === "mfrom",
        )
      : observations;
  if (!eligible.length)
    return unknown(
      mechanism === "spf" && observations.length
        ? "No MAIL FROM SPF result; HELO/null-envelope context is insufficient"
        : "No authentication results recorded",
    );
  let incomplete =
    mechanism === "spf" &&
    observations.some(
      (entry) =>
        entry.scope && entry.scope !== "mfrom" && entry.scope !== "helo",
    );
  const note =
    mechanism === "spf" && eligible.some((entry) => !entry.scope)
      ? "SPF scope omitted; assumed MAIL FROM"
      : null;
  for (const entry of eligible) {
    if (entry.result === "pass") {
      const aligned = domainsAlign(entry.domain, headerFrom, mode);
      if (aligned === true) return { result: "pass", note };
      if (aligned === null) incomplete = true;
    } else if (
      !entry.result ||
      ![
        "fail",
        ...(mechanism === "spf" ? ["softfail"] : []),
        "neutral",
        "none",
        "policy",
        "temperror",
        "permerror",
      ].includes(entry.result)
    )
      incomplete = true;
  }
  return incomplete
    ? unknown("Missing or invalid authentication evidence")
    : { result: "fail", note };
}

export function combinedAlignment(
  dkim: AlignmentResult,
  spf: AlignmentResult,
): AlignmentResult {
  if (dkim === "pass" || spf === "pass") return "pass";
  if (dkim === "fail" && spf === "fail") return "fail";
  return "unknown";
}
