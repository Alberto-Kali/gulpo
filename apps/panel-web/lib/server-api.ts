export type ProfileItem = {
  node_id: string;
  name: string;
  protocol: string;
  label: string;
  transport_mode?: string;
  server: string;
  port: number;
  method?: string;
  sni?: string;
  alpn?: string[];
  fingerprint?: string;
  flow?: string;
  public_key?: string;
  short_id?: string;
  obfs?: string;
  mask_host?: string;
  uuid?: string;
  client_password?: string;
  password_masked?: string;
  uri: string;
  last_seen_at?: string | null;
  status: string;
};

export type ProfilePageResponse = {
  user_name: string;
  user_status: string;
  subscription_token: string;
  profiles: ProfileItem[];
  message?: string;
};

function normalizeProfilesResponse(payload: ProfilePageResponse): ProfilePageResponse {
  return {
    ...payload,
    profiles: Array.isArray(payload.profiles) ? payload.profiles : [],
  };
}

function getInternalAPIBase() {
  return process.env.PANEL_API_INTERNAL_BASE_URL || "http://localhost:8080";
}

function forwardedSubscriptionHeaders(source?: Headers) {
  const headers: Record<string, string> = {};
  if (!source) return headers;
  const forwardKeys = [
    "user-agent",
    "accept",
    "accept-language",
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "x-hwid",
    "x-device-id",
    "x-device",
    "x-client-id",
    "x-client",
    "client-id",
    "device-id",
  ];
  for (const key of forwardKeys) {
    const value = source.get(key);
    if (value) {
      headers[key] = value;
    }
  }
  return headers;
}

export async function getSubjProfiles(token: string, request?: Request | Headers, search = ""): Promise<{ data?: ProfilePageResponse; error?: string; status: number }> {
  const sourceHeaders = request instanceof Request ? request.headers : request;
  const sourceURL = request instanceof Request ? new URL(request.url) : null;
  const query = sourceURL?.search ?? search;
  const response = await fetch(`${getInternalAPIBase()}/api/subj/${token}${query}`, {
    cache: "no-store",
    headers: forwardedSubscriptionHeaders(sourceHeaders),
  });

  if (!response.ok) {
    let error = response.statusText;
    try {
      const body = await response.json();
      error = body.error ?? error;
    } catch {}
    return { error, status: response.status };
  }

  return {
    data: normalizeProfilesResponse(await response.json()),
    status: response.status,
  };
}
