/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sky: {50:'#f0f3ff',100:'#e7ecff',200:'#cfd8fc',300:'#a9b9f4',400:'#8799ed',500:'#687ce6',600:'#4e61d6',700:'#4053c5',800:'#34439f',900:'#29367a',950:'#1c2450'},
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
        }
      }
    },
  },
  plugins: [],
}
