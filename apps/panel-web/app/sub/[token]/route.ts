import { getSubjProfiles } from "../../../lib/server-api";

export const dynamic = "force-dynamic";

const RAW_PROTOCOLS = new Set(["trojan", "hysteria2", "shadowsocks", "vless"]);

export async function GET(_: Request, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const result = await getSubjProfiles(token);

  if (!result.data) {
    return new Response(result.error ?? "not found", {
      status: result.status || 404,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  }

  const profiles = Array.isArray(result.data.profiles) ? result.data.profiles : [];
  const lines = profiles
    .filter((profile) => RAW_PROTOCOLS.has(profile.protocol))
    .map((profile) => profile.uri);
  const body = Buffer.from(lines.join("\n"), "utf-8").toString("base64");

  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
