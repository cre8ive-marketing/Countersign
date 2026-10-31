import { Lexend, Source_Sans_3, Geist_Mono, Mrs_Saint_Delafield } from 'next/font/google';

// next/font downloads these at build time and serves them from this server.
export const heading = Lexend({ subsets: ['latin'], variable: '--font-heading', display: 'swap' });
export const sans = Source_Sans_3({ subsets: ['latin'], variable: '--font-sans', display: 'swap' });
export const mono = Geist_Mono({ subsets: ['latin'], variable: '--font-mono', display: 'swap' });
export const script = Mrs_Saint_Delafield({ subsets: ['latin'], weight: '400', variable: '--font-script', display: 'block' });
