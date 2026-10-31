import Head from 'next/head';
import { heading, sans, mono, script } from '../lib/fonts';
import '../styles/globals.css';

export default function App({ Component, pageProps }) {
  return (
    <div className={`root ${heading.variable} ${sans.variable} ${mono.variable} ${script.variable}`}>
      <Head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
      </Head>
      <Component {...pageProps} />
    </div>
  );
}
