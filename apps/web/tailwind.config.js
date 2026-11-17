/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bgDark: '#090b10',
        cardDark: '#11151f',
        borderDark: '#1f2638',
        accentNeon: '#10b981',
        blockGreen: '#10b981',
        bypassRed: '#ef4444',
        amberShadow: '#f59e0b',
        mutedGray: '#64748b'
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}
