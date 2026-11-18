/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#070d18",
          900: "#0b1220",
          800: "#111c2f",
          700: "#1a2941",
        },
        signal: {
          cyan: "#67e8f9",
          blue: "#60a5fa",
          green: "#34d399",
          amber: "#fbbf24",
          red: "#fb7185",
        },
      },
      boxShadow: {
        glow: "0 0 36px rgba(96, 165, 250, 0.12)",
      },
    },
  },
  plugins: [],
};
