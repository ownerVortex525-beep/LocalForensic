import type {Metadata} from 'next';
import './globals.css'; // Global styles

export const metadata: Metadata = {
  title: 'Local Forensic Data Correlation Workbench',
  description: 'Authorized local-only cybersecurity and digital forensics data discovery, correlation, and privacy audit workbench.',
  openGraph: {
    title: 'Local Forensic Data Correlation Workbench',
    description: 'Authorized local-only cybersecurity and digital forensics data discovery, correlation, and privacy audit workbench.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Local Forensic Data Correlation Workbench',
    description: 'Authorized local-only cybersecurity and digital forensics data discovery, correlation, and privacy audit workbench.',
  },
};

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en">
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
