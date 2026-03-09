/** @type {import('tailwindcss').Config} */
export const content = [
  "./views/**/*.html",
  "./views/**/*.js",
];
export const theme = {
  extend: {
    colors: { primary: "#8A2BE2", secondary: "#4169E1" },
    borderRadius: {
      none: "0px",
      sm: "4px",
      DEFAULT: "8px",
      md: "12px",
      lg: "16px",
      xl: "20px",
      "2xl": "24px",
      "3xl": "32px",
      full: "9999px",
      button: "8px",
    },
  },
};
export const plugins = [];
