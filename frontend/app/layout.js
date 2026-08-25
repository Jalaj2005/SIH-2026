import { Space_Grotesk, Inter, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
  weight: ["500", "600", "700"],
});

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-mono-data",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata = {
  title: "DNS Sentinel — SOC Dashboard",
  description: "Module 6: SOC Web Dashboard for the AI-Powered DNS Filtering Service (SIH1524)",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body
        className={`${spaceGrotesk.variable} ${inter.variable} ${plexMono.variable} font-sans antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
