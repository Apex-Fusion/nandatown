import type { Metadata } from "next";
import { Geist, Geist_Mono, Instrument_Serif } from "next/font/google";
import "./globals.css";
import { Navbar } from "@/components/navbar";
import { Footer } from "@/components/footer";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const instrumentSerif = Instrument_Serif({
  variable: "--font-instrument",
  subsets: ["latin"],
  weight: ["400"],
  style: ["normal", "italic"],
  display: "swap",
});

const SITE_URL = "https://nandatown.projectnanda.org";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: "Nanda Town — by Project NANDA",
    template: "%s — Nanda Town",
  },
  description:
    "Nanda Town is an open-source sandbox where AI agents meet, talk, and work things out — run multi-agent simulations, write layer plugins, and test agent protocols. By Project NANDA.",
  keywords: [
    "AI agents",
    "multi-agent simulation",
    "agent protocols",
    "Project NANDA",
    "Nanda Town",
    "agent sandbox",
    "nest-core",
    "agentic commerce",
    "AI agent testing",
  ],
  applicationName: "Nanda Town",
  authors: [{ name: "Project NANDA", url: "https://projectnanda.org" }],
  creator: "Project NANDA",
  openGraph: {
    type: "website",
    url: SITE_URL,
    siteName: "Nanda Town",
    title: "Nanda Town — by Project NANDA",
    description:
      "An open-source sandbox where AI agents meet, talk, and work things out. Run multi-agent simulations, write layer plugins, and test agent protocols.",
    images: [
      {
        url: "/brand/nanda-logo-color.png",
        width: 500,
        height: 500,
        alt: "Nanda Town — a sandbox for AI agents, by Project NANDA",
      },
    ],
    locale: "en_US",
  },
  twitter: {
    card: "summary",
    title: "Nanda Town — by Project NANDA",
    description:
      "An open-source sandbox where AI agents meet, talk, and work things out.",
    images: ["/brand/nanda-logo-color.png"],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16.png", sizes: "16x16", type: "image/png" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

const organizationJsonLd = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "Project NANDA",
  url: "https://projectnanda.org",
  logo: `${SITE_URL}/brand/nanda-logo-color.png`,
  sameAs: ["https://github.com/projnanda"],
};

const webSiteJsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "Nanda Town",
  url: SITE_URL,
  description:
    "An open-source sandbox where AI agents meet, talk, and work things out. Run multi-agent simulations, write layer plugins, and test agent protocols.",
  publisher: { "@type": "Organization", name: "Project NANDA" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${instrumentSerif.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-cream-100 text-ink-900">
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationJsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(webSiteJsonLd) }}
        />
        <div className="flex min-h-screen flex-col md:flex-row">
          <Navbar />
          <div className="flex min-w-0 flex-1 flex-col">
            <main className="flex-1">{children}</main>
            <Footer />
          </div>
        </div>
      </body>
    </html>
  );
}
