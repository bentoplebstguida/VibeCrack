import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HackerPA - Security Scanner",
  description: "Plataforma de analise de seguranca para aplicacoes web",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR">
      <body className="antialiased bg-gray-950 text-gray-100">
        {children}
      </body>
    </html>
  );
}
