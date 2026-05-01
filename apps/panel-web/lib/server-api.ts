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

export async function getSubjProfiles(token: string): Promise<{ data?: ProfilePageResponse; error?: string; status: number }> {
  const response = await fetch(`${getInternalAPIBase()}/api/subj/${token}`, {
    cache: "no-store",
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
