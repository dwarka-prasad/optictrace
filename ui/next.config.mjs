/** @type {import('next').NextConfig} */
const nextConfig = {
  // Static export: `next build` emits ui/out, which the Go agent serves
  // from its admin listener — one binary ships the whole product.
  output: 'export',
  images: { unoptimized: true },
  trailingSlash: false,
};

export default nextConfig;
