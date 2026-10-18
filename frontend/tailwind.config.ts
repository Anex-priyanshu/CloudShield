import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        page: "#0B1220",
        card: "#111B2E",
        "card-hover": "#1A2740",
        "card-subtle": "#162238",
        border: "#24324D",
        "primary-blue": "#3B82F6",
        "accent-cyan": "#22D3EE",
        "text-main": "#E5EAF3",
        "text-muted": "#93A1BC",
        critical: "#DC2626",
        high: "#EA580C",
        medium: "#CA8A04",
        low: "#2563EB",
        ok: "#16A34A",
      },
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        mono: ["JetBrains Mono", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
