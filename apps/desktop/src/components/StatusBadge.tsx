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

export function AlertStatusBadge({ status }: { status: string }) {
  const st = status.toUpperCase();
  let className = "badge badge-neutral";
  if (st === "OPEN") className = "badge badge-alert";
  else if (st === "ACKNOWLEDGED") className = "badge badge-warning";
  else if (st === "RESOLVED") className = "badge badge-success";
  else if (st === "FALSE_POSITIVE") className = "badge badge-neutral";

  return <span className={className}>{st.replace("_", " ")}</span>;
}

export function RuleCategoryBadge({ category }: { category: string }) {
  const cat = category.toUpperCase();
  let className = "badge badge-notice";
  if (cat === "AUTH") className = "badge badge-warning";
  else if (cat === "PRIVILEGE") className = "badge badge-alert";
  else if (cat === "PROCESS") className = "badge badge-notice";
  else if (cat === "ACCOUNT") className = "badge badge-neutral";
  else if (cat === "NETWORK") className = "badge badge-notice";

  return <span className={className}>{cat}</span>;
}

