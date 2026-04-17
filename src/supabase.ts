import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let cachedSupabase: SupabaseClient | null = null;

const sharedAuthOptions = {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false
  }
} as const;

function getSupabaseUrl() {
  return process.env.SUPABASE_URL as string;
}

function getSupabaseServiceRoleKey() {
  return process.env.SUPABASE_SERVICE_ROLE_KEY as string;
}

function getSupabaseAuthKey() {
  return (process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY) as string;
}

export function getSupabaseConfigError(): string | null {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceKey) {
    return "Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY";
  }
  if (supabaseServiceKey.startsWith("sb_publishable")) {
    return "SUPABASE_SERVICE_ROLE_KEY must be a service role key, not publishable.";
  }
  return null;
}

export function getSupabase() {
  const configError = getSupabaseConfigError();
  if (configError) throw new Error(configError);
  if (!cachedSupabase) {
    cachedSupabase = createClient(getSupabaseUrl(), getSupabaseServiceRoleKey(), sharedAuthOptions);
  }
  return cachedSupabase;
}

// Create a fresh auth client for password sign-in calls so user sessions
// never replace the shared service-role session used for database access.
export function createSupabaseAuthClient() {
  const configError = getSupabaseConfigError();
  if (configError) throw new Error(configError);
  return createClient(getSupabaseUrl(), getSupabaseAuthKey(), sharedAuthOptions);
}

export const supabase = new Proxy({} as SupabaseClient, {
  get(_target, prop) {
    const client = getSupabase();
    const value = Reflect.get(client, prop);
    return typeof value === "function" ? value.bind(client) : value;
  }
});
