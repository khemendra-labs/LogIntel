/**
 * LogIntel System-Aware Theme Management
 *
 * Implements persistent theme preferences (System, Light, Dark) with automatic
 * detection of the host OS preference (via window.matchMedia) and live listeners
 * that update the UI without requiring an application restart.
 */

import { useEffect, useState } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type EffectiveTheme = "light" | "dark";

export const THEME_STORAGE_KEY = "logintel-theme-preference";

function getWindow(): any {
  if (typeof window !== "undefined") return window;
  if (typeof globalThis !== "undefined" && (globalThis as any).window) return (globalThis as any).window;
  return undefined;
}

function getDocument(): any {
  if (typeof document !== "undefined") return document;
  if (typeof globalThis !== "undefined" && (globalThis as any).document) return (globalThis as any).document;
  return undefined;
}

function getStorage(): any {
  const win = getWindow();
  if (win && win.localStorage) return win.localStorage;
  if (typeof globalThis !== "undefined" && (globalThis as any).localStorage) return (globalThis as any).localStorage;
  return undefined;
}

/**
 * Returns the effective theme currently preferred by the operating system / desktop portal.
 */
export function getSystemTheme(): EffectiveTheme {
  const win = getWindow();
  if (!win || typeof win.matchMedia !== "function") {
    return "light";
  }
  try {
    const mq = win.matchMedia("(prefers-color-scheme: dark)");
    return mq && mq.matches ? "dark" : "light";
  } catch {
    return "light";
  }
}

/**
 * Reads the explicitly stored theme preference from localStorage, defaulting to 'system'.
 */
export function getStoredThemePreference(): ThemePreference {
  const storage = getStorage();
  if (!storage) {
    return "system";
  }
  try {
    const stored = storage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") {
      return stored;
    }
  } catch (err) {
    console.warn("Unable to access localStorage for theme preference:", err);
  }
  return "system";
}

/**
 * Applies the given theme preference to document.documentElement.
 * When preference is 'system', the data-theme override is cleared, allowing CSS
 * @media (prefers-color-scheme: dark) to natively govern the appearance.
 * Returns the resulting effective theme.
 */
export function applyTheme(preference: ThemePreference): EffectiveTheme {
  const doc = getDocument();
  if (!doc || !doc.documentElement) {
    return "light";
  }

  const root = doc.documentElement;
  let effective: EffectiveTheme;

  if (preference === "dark") {
    root.setAttribute("data-theme", "dark");
    effective = "dark";
  } else if (preference === "light") {
    root.setAttribute("data-theme", "light");
    effective = "light";
  } else {
    // 'system'
    root.removeAttribute("data-theme");
    effective = getSystemTheme();
  }

  root.setAttribute("data-theme-preference", preference);

  try {
    const storage = getStorage();
    if (storage) {
      storage.setItem(THEME_STORAGE_KEY, preference);
    }
  } catch (err) {
    console.warn("Unable to persist theme preference to localStorage:", err);
  }

  return effective;
}

/**
 * Synchronous pre-render initialization script for index.html / main.tsx.
 * Executes before React mounts to eliminate any visible theme flash.
 */
export function initTheme(): EffectiveTheme {
  const pref = getStoredThemePreference();
  return applyTheme(pref);
}

/**
 * React hook to observe and change the active theme preference.
 * Listens for live host OS theme toggles when in 'system' mode.
 */
export function useTheme() {
  const [preference, setPreferenceState] = useState<ThemePreference>(getStoredThemePreference);
  const [effectiveTheme, setEffectiveTheme] = useState<EffectiveTheme>(() => {
    return preference === "system" ? getSystemTheme() : preference;
  });

  useEffect(() => {
    const eff = applyTheme(preference);
    setEffectiveTheme(eff);

    const win = getWindow();
    if (!win || typeof win.matchMedia !== "function") return;

    const mediaQuery = win.matchMedia("(prefers-color-scheme: dark)");

    const handleSystemChange = () => {
      const stored = getStoredThemePreference();
      if (stored === "system") {
        const newEff = mediaQuery && mediaQuery.matches ? "dark" : "light";
        setEffectiveTheme(newEff);
        applyTheme("system");
      }
    };

    if (mediaQuery && mediaQuery.addEventListener) {
      mediaQuery.addEventListener("change", handleSystemChange);
      return () => mediaQuery.removeEventListener("change", handleSystemChange);
    } else if (mediaQuery && (mediaQuery as any).addListener) {
      (mediaQuery as any).addListener(handleSystemChange);
      return () => (mediaQuery as any).removeListener(handleSystemChange);
    }
  }, [preference]);

  const setPreference = (newPref: ThemePreference) => {
    setPreferenceState(newPref);
    const eff = applyTheme(newPref);
    setEffectiveTheme(eff);
  };

  return {
    preference,
    effectiveTheme,
    setPreference,
  };
}
