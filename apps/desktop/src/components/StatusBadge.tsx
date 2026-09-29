import React from "react";
import { Outcome, Severity } from "../types/events";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const sev = severity.toUpperCase();
  let className = "badge badge-neutral";
  if (sev === "ALERT" || sev === "CRITICAL") className = "badge badge-alert";
  else if (sev === "WARNING") className = "badge badge-warning";
  else if (sev === "NOTICE" || sev === "INFORMATIONAL") className = "badge badge-notice";

  return <span className={className}>{sev}</span>;
}

export function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  const out = outcome.toUpperCase();
  let className = "badge badge-neutral";
  if (out === "SUCCESS") className = "badge badge-success";
  else if (out === "FAILURE") className = "badge badge-failure";
  else if (out === "ATTEMPT") className = "badge badge-warning";

  return <span className={className}>{out}</span>;
}
