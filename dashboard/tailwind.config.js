/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        hydra: {
          bg: '#0a0e1a',
          surface: '#111827',
          border: '#1f2937',
          accent: '#06b6d4',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          muted: '#6b7280',
        },
      },
    },
  },
  plugins: [],
}
