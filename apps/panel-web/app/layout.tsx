import "./globals.css";
import type { Metadata } from "next";
import type { CSSProperties, ReactNode } from "react";

export const metadata: Metadata = {
  title: "Gulpo Panel",
  description: "sing-box control panel MVP",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={
          {
            "--font-display": '"Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif',
            "--font-text": '"Avenir Next", "Segoe UI", "Helvetica Neue", Arial, sans-serif',
          } as CSSProperties
        }
      >
        {children}
      </body>
    </html>
  );
}
