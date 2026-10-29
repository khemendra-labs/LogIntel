import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyTheme,
  getStoredThemePreference,
  getSystemTheme,
  initTheme,
  THEME_STORAGE_KEY,
} from "../lib/theme";

describe("Theme Management Library", () => {
  let mockStorage: Record<string, string>;
  let mockAttributes: Record<string, string>;

  beforeEach(() => {
    vi.restoreAllMocks();

    mockStorage = {};
    mockAttributes = {};

    globalThis.localStorage = {
      getItem: (key: string) => mockStorage[key] || null,
      setItem: (key: string, val: string) => {
        mockStorage[key] = String(val);
      },
      removeItem: (key: string) => {
        delete mockStorage[key];
      },
      clear: () => {
        for (const k of Object.keys(mockStorage)) delete mockStorage[k];
      },
      length: 0,
      key: () => null,
    };

    globalThis.document = {
      documentElement: {
        setAttribute: (k: string, v: string) => {
          mockAttributes[k] = v;
        },
        getAttribute: (k: string) => mockAttributes[k] || null,
        removeAttribute: (k: string) => {
          delete mockAttributes[k];
        },
        hasAttribute: (k: string) => k in mockAttributes,
      },
    } as any;

    globalThis.window = {
      localStorage: globalThis.localStorage,
      matchMedia: vi.fn().mockImplementation((query: string) => ({
        matches: query.includes("dark"),
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    } as any;
  });

  it("defaults to 'system' when no preference is stored", () => {
    expect(getStoredThemePreference()).toBe("system");
  });

  it("retrieves valid stored theme preferences", () => {
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    expect(getStoredThemePreference()).toBe("dark");

    localStorage.setItem(THEME_STORAGE_KEY, "light");
    expect(getStoredThemePreference()).toBe("light");

    localStorage.setItem(THEME_STORAGE_KEY, "system");
    expect(getStoredThemePreference()).toBe("system");

    localStorage.setItem(THEME_STORAGE_KEY, "invalid-theme");
    expect(getStoredThemePreference()).toBe("system");
  });

  it("applies dark theme explicitly to document element and persists choice", () => {
    const effective = applyTheme("dark");
    expect(effective).toBe("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(document.documentElement.getAttribute("data-theme-preference")).toBe("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });

  it("applies light theme explicitly to document element and persists choice", () => {
    const effective = applyTheme("light");
    expect(effective).toBe("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    expect(document.documentElement.getAttribute("data-theme-preference")).toBe("light");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
  });

  it("removes data-theme attribute in system mode to allow CSS media queries to govern", () => {
    applyTheme("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");

    applyTheme("system");
    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
    expect(document.documentElement.getAttribute("data-theme-preference")).toBe("system");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("system");
  });

  it("detects system theme accurately via matchMedia", () => {
    expect(getSystemTheme()).toBe("dark");

    window.matchMedia = vi.fn().mockImplementation(() => ({
      matches: false,
      media: "",
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }));

    expect(getSystemTheme()).toBe("light");
  });

  it("initTheme applies the stored preference upon startup", () => {
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    initTheme();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });
});
