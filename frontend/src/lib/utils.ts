import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Strip the depscanner worker's ephemeral clone root
 *  (os.tmpdir()/deptex-extract-XXXX/) from a finding's file path so the UI shows
 *  a repo-relative path instead of leaking a /tmp/... prefix. Returns the path
 *  unchanged when it's already relative. */
export function cleanFilePath(p: string | null | undefined): string {
  if (!p) return "";
  return p.replace(/^.*?deptex-extract-[^/\\]+[/\\]/, "");
}

