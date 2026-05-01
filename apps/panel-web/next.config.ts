import type { NextConfig } from "next";

const basePath = process.env.NEXT_PUBLIC_PANEL_BASE_PATH || "";

const nextConfig: NextConfig = {
  basePath,
  experimental: {
    typedRoutes: true,
  },
};

export default nextConfig;
