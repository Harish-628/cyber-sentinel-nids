import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CYBER SENTINEL // Intelligent NIDS SOC Dashboard",
  description: "Enterprise Network Intrusion Detection System powered by Machine Learning and CIC-IDS2017 dataset",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
      </head>
      <body className="bg-[#08090d] text-zinc-300 min-h-screen antialiased selection:bg-red-900/50 selection:text-white">
        {children}
      </body>
    </html>
  );
}
