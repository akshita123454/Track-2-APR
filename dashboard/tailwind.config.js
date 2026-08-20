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
        /* HydraDB brand palette: near-black canvas, ember orange accent. */
        hg: {
          black: '#000000',
          void: '#050505',
          panel: '#0b0b0c',
          raised: '#121214',
          line: '#232326',
          ember: '#ff5b1a',
          flame: '#ff7a33',
          amber: '#ffa028',
          ash: '#8a8a92',
          bone: '#ededf0',
        },
      },
      fontFamily: {
        display: ['"DM Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
