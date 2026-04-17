import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import { createSupabaseAuthClient, getSupabaseConfigError, supabase } from "./supabase.js";
import { getJwtConfigError, requireAdmin, requireAuth, requireSuperAdmin, signAdminToken, signToken, type AuthedRequest } from "./auth.js";
import type { Candidate } from "./types.js";

const app = express();
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use("/api", (_req, res, next) => {
  const configError = getJwtConfigError() || getSupabaseConfigError();
  if (configError) {
    return res.status(500).json({ error: configError });
  }
  return next();
});

const staticRoot = path.resolve(process.cwd());
app.use(express.static(staticRoot));

const allowedAdminRoles = new Set(["admin", "superadmin", "hr"]);
const signedMediaBuckets = new Set(["cms"]);

function buildMediaProxyUrl(bucket: string, objectPath: string) {
  return `/api/media?bucket=${encodeURIComponent(bucket)}&path=${encodeURIComponent(objectPath)}`;
}

function extractStorageObjectPath(value: unknown, bucket = "cms"): string | null {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  const publicPrefix = `/storage/v1/object/public/${bucket}/`;
  const signPrefix = `/storage/v1/object/sign/${bucket}/`;

  if (raw.startsWith(publicPrefix)) {
    return decodeURIComponent(raw.slice(publicPrefix.length));
  }
  if (raw.startsWith(signPrefix)) {
    return decodeURIComponent(raw.slice(signPrefix.length));
  }
  if (/^https?:\/\//i.test(raw)) {
    try {
      const parsed = new URL(raw);
      if (parsed.pathname.startsWith(publicPrefix)) {
        return decodeURIComponent(parsed.pathname.slice(publicPrefix.length));
      }
      if (parsed.pathname.startsWith(signPrefix)) {
        return decodeURIComponent(parsed.pathname.slice(signPrefix.length));
      }
    } catch {
      return null;
    }
    return null;
  }
  if (!raw.startsWith("/") && !raw.startsWith("data:")) {
    return raw.replace(/^\/+/, "");
  }
  return null;
}

function resolveCmsAssetUrl(value: unknown) {
  const raw = String(value ?? "").trim();
  if (!raw) return raw;
  const objectPath = extractStorageObjectPath(raw, "cms");
  return objectPath ? buildMediaProxyUrl("cms", objectPath) : raw;
}

function sanitizeCandidate(row: any): Candidate {
  return {
    id: row.id,
    first_name: row.first_name,
    last_name: row.last_name,
    name: row.name,
    email: row.email,
    phone: row.phone,
    dob: row.dob,
    city: row.city,
    qualification: row.qualification,
    department: row.department,
    cv: row.cv,
    documents: row.documents || [],
    registered_at: row.registered_at
  };
}

function getCandidatePasswordHash(row: any): string | null {
  return typeof row?.password_hash === "string" && row.password_hash.trim() ? row.password_hash : null;
}

function isBcryptHash(value: string | null): boolean {
  return Boolean(value && /^\$2[aby]\$\d{2}\$/.test(value));
}

function getAuthProfile(user: { user_metadata?: Record<string, unknown> | null }) {
  const meta = user.user_metadata as Record<string, unknown> | null;
  const fullName = String(meta?.full_name || meta?.name || "").trim();
  const [fn, ...ln] = fullName ? fullName.split(" ") : [];
  const firstName = String(meta?.first_name || fn || "Candidate").trim();
  const lastName = String(meta?.last_name || ln.join(" ") || "User").trim();

  return {
    firstName,
    lastName,
    name: `${firstName} ${lastName}`.trim(),
    phone: meta?.phone ? String(meta.phone) : null,
    dob: meta?.dob ? String(meta.dob) : null,
    city: meta?.city ? String(meta.city) : null,
    qualification: meta?.qualification ? String(meta.qualification) : null,
    department: meta?.department ? String(meta.department) : null
  };
}

async function signInWithSupabasePassword(email: string, password: string) {
  const authClient = createSupabaseAuthClient();
  return authClient.auth.signInWithPassword({
    email,
    password
  });
}

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/media", async (req, res) => {
  const bucket = String(req.query.bucket || "").trim();
  const objectPath = String(req.query.path || "").trim().replace(/^\/+/, "");

  if (!signedMediaBuckets.has(bucket) || !objectPath) {
    return res.status(400).json({ error: "Invalid media request." });
  }

  const { data, error } = await supabase.storage.from(bucket).createSignedUrl(objectPath, 60 * 60);
  if (error || !data?.signedUrl) {
    return res.status(404).json({ error: error?.message || "Media not found." });
  }

  res.set("Cache-Control", "public, max-age=300");
  return res.redirect(data.signedUrl);
});

app.post("/api/auth/signup", async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    phone,
    dob,
    city,
    qualification,
    department,
    password
  } = req.body || {};

  if (!firstName || !lastName || !email || !phone || !password) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  const emailLower = String(email).trim().toLowerCase();

  const { data: existing, error: existingErr } = await supabase
    .from("candidates")
    .select("id")
    .eq("email", emailLower)
    .maybeSingle();

  if (existingErr) {
    return res.status(500).json({ error: existingErr.message });
  }
  if (existing) {
    return res.status(409).json({ error: "Account already exists." });
  }

  const passwordHash = await bcrypt.hash(String(password), 10);
  const name = `${firstName} ${lastName}`.trim();

  const { data, error } = await supabase
    .from("candidates")
    .insert({
      first_name: firstName,
      last_name: lastName,
      name,
      email: emailLower,
      phone,
      dob: dob || null,
      city: city || null,
      qualification: qualification || null,
      department: department || null,
      password_hash: passwordHash
    })
    .select()
    .single();

  if (error || !data) {
    return res.status(500).json({ error: error?.message || "Signup failed." });
  }

  const token = signToken(data.id);
  return res.json({ token, user: sanitizeCandidate(data) });
});

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Missing email or password." });
    }
    const { data, error } = await signInWithSupabasePassword(String(email).trim().toLowerCase(), String(password));
    if (error || !data?.user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }
    const role =
      (data.user.app_metadata as { role?: string } | undefined)?.role ||
      (data.user.user_metadata as { role?: string } | undefined)?.role ||
      "";
    if (!allowedAdminRoles.has(String(role))) {
      return res.status(403).json({ error: "Admin access not granted." });
    }
    const token = signAdminToken(String(role));
    return res.json({ token, role });
  } catch (routeError: any) {
    // eslint-disable-next-line no-console
    console.error("Admin login failed unexpectedly:", routeError);
    return res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/auth/signin", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Missing email or password." });
    }

    const rawPassword = String(password);
    const emailLower = String(email).trim().toLowerCase();

    const { data, error } = await supabase
      .from("candidates")
      .select("*")
      .eq("email", emailLower)
      .maybeSingle();

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    const storedHash = getCandidatePasswordHash(data);
    let localPasswordValid = false;

    if (data && isBcryptHash(storedHash)) {
      try {
        localPasswordValid = await bcrypt.compare(rawPassword, storedHash as string);
      } catch (compareError) {
        // eslint-disable-next-line no-console
        console.error("Candidate password hash comparison failed:", compareError);
      }
    }

    if (data && localPasswordValid) {
      const token = signToken(data.id);
      return res.json({ token, user: sanitizeCandidate(data) });
    }

    const { data: authData, error: authErr } = await signInWithSupabasePassword(emailLower, rawPassword);

    if (authErr || !authData?.user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const passwordHash = await bcrypt.hash(rawPassword, 10);

    if (!data) {
      const profile = getAuthProfile(authData.user);
      const { data: created, error: createErr } = await supabase
        .from("candidates")
        .insert({
          first_name: profile.firstName,
          last_name: profile.lastName,
          name: profile.name,
          email: emailLower,
          phone: profile.phone,
          dob: profile.dob,
          city: profile.city,
          qualification: profile.qualification,
          department: profile.department,
          password_hash: passwordHash
        })
        .select()
        .single();

      if (createErr || !created) {
        // If a candidate row already exists (race/duplicate), fetch and continue.
        if (createErr?.code === "23505") {
          const { data: existingCandidate, error: existingCandidateErr } = await supabase
            .from("candidates")
            .select("*")
            .eq("email", emailLower)
            .maybeSingle();

          if (existingCandidateErr) {
            return res.status(500).json({ error: existingCandidateErr.message });
          }
          if (existingCandidate) {
            const token = signToken(existingCandidate.id);
            return res.json({ token, user: sanitizeCandidate(existingCandidate) });
          }
        }
        return res.status(500).json({ error: createErr?.message || "Sync failed." });
      }

      const token = signToken(created.id);
      return res.json({ token, user: sanitizeCandidate(created) });
    }

    if (!localPasswordValid) {
      const { error: updateErr } = await supabase
        .from("candidates")
        .update({ password_hash: passwordHash })
        .eq("id", data.id);

      if (updateErr) {
        // eslint-disable-next-line no-console
        console.error("Failed to refresh candidate password hash:", updateErr);
      }
    }

    const token = signToken(data.id);
    return res.json({ token, user: sanitizeCandidate(data) });
  } catch (routeError: any) {
    // eslint-disable-next-line no-console
    console.error("Candidate sign-in failed unexpectedly:", routeError);
    return res.status(500).json({ error: "Sign-in failed." });
  }
});

app.get("/api/me", requireAuth, async (req: AuthedRequest, res) => {
  const userId = req.userId as string;
  const { data, error } = await supabase
    .from("candidates")
    .select("*")
    .eq("id", userId)
    .single();

  if (error || !data) {
    return res.status(404).json({ error: "User not found." });
  }

  return res.json({ user: sanitizeCandidate(data) });
});

app.put("/api/me", requireAuth, async (req: AuthedRequest, res) => {
  const userId = req.userId as string;
  const {
    name,
    phone,
    dob,
    city,
    qualification,
    department,
    cv,
    documents
  } = req.body || {};

  const update: Record<string, unknown> = {};
  if (name !== undefined) update.name = name;
  if (phone !== undefined) update.phone = phone;
  if (dob !== undefined) update.dob = dob || null;
  if (city !== undefined) update.city = city || null;
  if (qualification !== undefined) update.qualification = qualification || null;
  if (department !== undefined) update.department = department || null;
  if (cv !== undefined) update.cv = cv || null;
  if (documents !== undefined) update.documents = documents || [];

  const { data, error } = await supabase
    .from("candidates")
    .update(update)
    .eq("id", userId)
    .select()
    .single();

  if (error || !data) {
    return res.status(500).json({ error: error?.message || "Update failed." });
  }

  return res.json({ user: sanitizeCandidate(data) });
});

app.get("/api/applications", requireAuth, async (req: AuthedRequest, res) => {
  const userId = req.userId as string;
  const { data, error } = await supabase
    .from("applications")
    .select("*")
    .eq("candidate_id", userId)
    .order("applied_at", { ascending: false });

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  return res.json({ applications: data || [] });
});

app.post("/api/applications", requireAuth, async (req: AuthedRequest, res) => {
  const userId = req.userId as string;
  const {
    jobKey,
    jobTitle,
    jobDept,
    qualification,
    experience,
    location,
    note,
    cvFile
  } = req.body || {};

  if (!jobKey || !jobTitle) {
    return res.status(400).json({ error: "Missing job details." });
  }

  const { data: existing, error: existingErr } = await supabase
    .from("applications")
    .select("id")
    .eq("candidate_id", userId)
    .eq("job_key", jobKey)
    .maybeSingle();

  if (existingErr) {
    return res.status(500).json({ error: existingErr.message });
  }
  if (existing) {
    return res.status(409).json({ error: "Already applied." });
  }

  const { data, error } = await supabase
    .from("applications")
    .insert({
      candidate_id: userId,
      job_key: jobKey,
      job_title: jobTitle,
      job_dept: jobDept || null,
      qualification: qualification || null,
      experience: experience || null,
      location: location || null,
      note: note || null,
      cv_file: cvFile || null,
      status: "Under Review"
    })
    .select()
    .single();

  if (error || !data) {
    return res.status(500).json({ error: error?.message || "Submit failed." });
  }

  return res.json({ application: data });
});

app.get("/api/applications/summary", async (_req, res) => {
  const { data, error } = await supabase
    .from("applications")
    .select("job_key");

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  const perJob: Record<string, number> = {};
  (data || []).forEach((row) => {
    const key = row.job_key || "unknown";
    perJob[key] = (perJob[key] || 0) + 1;
  });
  const totalApplications = (data || []).length;

  return res.json({ totalApplications, perJob });
});

app.get("/api/jobs", async (_req, res) => {
  const { data, error } = await supabase
    .from("jobs")
    .select("*")
    .eq("is_active", true)
    .order("created_at", { ascending: false });
  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.json({ jobs: data || [] });
});

app.post("/api/contact", async (req, res) => {
  const { firstName, lastName, email, phone, service, details } = req.body || {};
  if (!firstName || !lastName || !email) {
    return res.status(400).json({ error: "Missing required fields." });
  }

  const { error } = await supabase.from("enquiries").insert({
    first_name: firstName,
    last_name: lastName,
    email,
    phone: phone || null,
    service: service || null,
    details: details || null
  });

  if (error) {
    return res.status(500).json({ error: error.message });
  }

  return res.json({ ok: true });
});

app.get("/api/admin/jobs", requireAdmin, async (_req, res) => {
  const { data, error } = await supabase
    .from("jobs")
    .select("*")
    .order("created_at", { ascending: false });
  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.json({ jobs: data || [] });
});

app.post("/api/admin/jobs", requireAdmin, async (req, res) => {
  const {
    job_key,
    title,
    dept,
    dept_icon,
    tags,
    description,
    requirements,
    qualification,
    experience,
    location,
    status,
    is_active
  } = req.body || {};

  if (!job_key || !title) {
    return res.status(400).json({ error: "Missing job_key or title." });
  }

  const { data, error } = await supabase
    .from("jobs")
    .insert({
      job_key,
      title,
      dept: dept || null,
      dept_icon: dept_icon || null,
      tags: tags || [],
      description: description || null,
      requirements: requirements || [],
      qualification: qualification || null,
      experience: experience || null,
      location: location || null,
      status: status || "Open",
      is_active: is_active !== undefined ? Boolean(is_active) : true
    })
    .select()
    .single();

  if (error || !data) {
    return res.status(500).json({ error: error?.message || "Create failed." });
  }
  return res.json({ job: data });
});

app.put("/api/admin/jobs/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const update = { ...req.body, updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from("jobs")
    .update(update)
    .eq("id", id)
    .select()
    .single();
  if (error || !data) {
    return res.status(500).json({ error: error?.message || "Update failed." });
  }
  return res.json({ job: data });
});

app.delete("/api/admin/jobs/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("jobs")
    .update({ is_active: false, updated_at: new Date().toISOString() })
    .eq("id", id)
    .select()
    .single();
  if (error || !data) {
    return res.status(500).json({ error: error?.message || "Delete failed." });
  }
  return res.json({ job: data });
});

app.get("/api/admin/applications", requireAdmin, async (_req, res) => {
  const { data, error } = await supabase
    .from("applications")
    .select("*, candidates(*)")
    .order("applied_at", { ascending: false });
  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.json({ applications: data || [] });
});

app.get("/api/content/:slug", async (req, res) => {
  const slug = String(req.params.slug || "").trim();
  if (!slug) {
    return res.status(400).json({ error: "Missing slug." });
  }

  const { data: page, error: pageErr } = await supabase
    .from("cms_pages")
    .select("*")
    .eq("slug", slug)
    .maybeSingle();
  if (pageErr) {
    return res.status(500).json({ error: pageErr.message });
  }

  let sections: any[] = [];
  if (page?.id) {
    const { data: sectionRows, error: sectionErr } = await supabase
      .from("cms_sections")
      .select("*")
      .eq("page_id", page.id)
      .eq("is_active", true)
      .order("sort_order", { ascending: true });
    if (sectionErr) {
      return res.status(500).json({ error: sectionErr.message });
    }
    const sectionIds = (sectionRows || []).map((s) => s.id);
    let items: any[] = [];
    if (sectionIds.length) {
      const { data: itemRows, error: itemErr } = await supabase
        .from("cms_items")
        .select("*")
        .in("section_id", sectionIds)
        .eq("is_active", true)
        .order("sort_order", { ascending: true });
      if (itemErr) {
        return res.status(500).json({ error: itemErr.message });
      }
      items = itemRows || [];
    }
    sections = (sectionRows || []).map((s) => ({
      ...s,
      items: items
        .filter((i) => i.section_id === s.id)
        .map((i) => ({
          ...i,
          image_url: resolveCmsAssetUrl(i.image_url)
        }))
    }));
  }

  const { data: settingsRows, error: settingsErr } = await supabase
    .from("cms_settings")
    .select("*");
  if (settingsErr) {
    return res.status(500).json({ error: settingsErr.message });
  }
  const settings: Record<string, string> = {};
  (settingsRows || []).forEach((r: any) => {
    const key = String(r.key);
    const value = String(r.value ?? "");
    settings[key] = key === "brand_logo" ? resolveCmsAssetUrl(value) : value;
  });

  return res.json({ page, sections, settings });
});

app.get("/api/admin/pages", requireAdmin, async (_req, res) => {
  const { data, error } = await supabase.from("cms_pages").select("*").order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ pages: data || [] });
});

app.post("/api/admin/pages", requireAdmin, async (req, res) => {
  const { slug, title, is_active } = req.body || {};
  if (!slug) return res.status(400).json({ error: "Missing slug." });
  const { data, error } = await supabase
    .from("cms_pages")
    .insert({
      slug: String(slug).trim(),
      title: title || null,
      is_active: is_active !== undefined ? Boolean(is_active) : true
    })
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Create failed." });
  return res.json({ page: data });
});

app.put("/api/admin/pages/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const update = { ...req.body, updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from("cms_pages")
    .update(update)
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Update failed." });
  return res.json({ page: data });
});

app.delete("/api/admin/pages/:id", requireSuperAdmin, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("cms_pages")
    .delete()
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Delete failed." });
  return res.json({ page: data });
});

app.get("/api/admin/sections", requireAdmin, async (_req, res) => {
  const { data, error } = await supabase
    .from("cms_sections")
    .select("*, cms_pages(slug)")
    .order("sort_order", { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ sections: data || [] });
});

app.post("/api/admin/sections", requireAdmin, async (req, res) => {
  const { page_id, key, title, subtitle, body, sort_order, is_active, settings } = req.body || {};
  if (!page_id || !key) return res.status(400).json({ error: "Missing page_id or key." });
  const { data, error } = await supabase
    .from("cms_sections")
    .insert({
      page_id,
      key,
      title: title || null,
      subtitle: subtitle || null,
      body: body || null,
      sort_order: Number(sort_order || 0),
      is_active: is_active !== undefined ? Boolean(is_active) : true,
      settings: settings || {}
    })
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Create failed." });
  return res.json({ section: data });
});

app.put("/api/admin/sections/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const update = { ...req.body, updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from("cms_sections")
    .update(update)
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Update failed." });
  return res.json({ section: data });
});

app.delete("/api/admin/sections/:id", requireSuperAdmin, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("cms_sections")
    .delete()
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Delete failed." });
  return res.json({ section: data });
});

app.get("/api/admin/items", requireAdmin, async (_req, res) => {
  const { data, error } = await supabase
    .from("cms_items")
    .select("*, cms_sections(key)")
    .order("sort_order", { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ items: data || [] });
});

app.post("/api/admin/items", requireAdmin, async (req, res) => {
  const {
    section_id,
    title,
    subtitle,
    body,
    image_url,
    link_url,
    link_label,
    tags,
    meta,
    sort_order,
    is_active
  } = req.body || {};
  if (!section_id) return res.status(400).json({ error: "Missing section_id." });
  const { data, error } = await supabase
    .from("cms_items")
    .insert({
      section_id,
      title: title || null,
      subtitle: subtitle || null,
      body: body || null,
      image_url: image_url || null,
      link_url: link_url || null,
      link_label: link_label || null,
      tags: tags || [],
      meta: meta || {},
      sort_order: Number(sort_order || 0),
      is_active: is_active !== undefined ? Boolean(is_active) : true
    })
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Create failed." });
  return res.json({ item: data });
});

app.put("/api/admin/items/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;
  const update = { ...req.body, updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from("cms_items")
    .update(update)
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Update failed." });
  return res.json({ item: data });
});

app.delete("/api/admin/items/:id", requireSuperAdmin, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("cms_items")
    .delete()
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Delete failed." });
  return res.json({ item: data });
});

app.get("/api/admin/settings", requireAdmin, async (_req, res) => {
  const { data, error } = await supabase.from("cms_settings").select("*").order("key", { ascending: true });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({
    settings: (data || []).map((row) => ({
      ...row,
      value: row.key === "brand_logo" ? resolveCmsAssetUrl(row.value) : row.value
    }))
  });
});

app.post("/api/admin/settings", requireAdmin, async (req, res) => {
  const { key, value } = req.body || {};
  if (!key) return res.status(400).json({ error: "Missing key." });
  const { data, error } = await supabase
    .from("cms_settings")
    .upsert({ key: String(key).trim(), value: value ?? null, updated_at: new Date().toISOString() }, { onConflict: "key" })
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Upsert failed." });
  return res.json({ setting: data });
});

app.delete("/api/admin/settings/:id", requireSuperAdmin, async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("cms_settings")
    .delete()
    .eq("id", id)
    .select()
    .single();
  if (error || !data) return res.status(500).json({ error: error?.message || "Delete failed." });
  return res.json({ setting: data });
});

app.post("/api/admin/upload", requireSuperAdmin, async (req, res) => {
  const { filename, contentType, data } = req.body || {};
  if (!filename || !data) {
    return res.status(400).json({ error: "Missing file data." });
  }
  const safeName = String(filename).replace(/[^a-zA-Z0-9._-]/g, "_");
  const path = `uploads/${Date.now()}-${safeName}`;
  const buffer = Buffer.from(String(data), "base64");
  const { error } = await supabase.storage.from("cms").upload(path, buffer, {
    contentType: contentType || "application/octet-stream",
    upsert: true
  });
  if (error) {
    return res.status(500).json({ error: error.message });
  }
  return res.json({ path, url: buildMediaProxyUrl("cms", path) });
});

export default app;

const isDirectRun = Boolean(process.argv[1]) && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isDirectRun) {
  const port = Number(process.env.PORT || 4000);
  const server = app.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`API server running on http://localhost:${port}`);
  });

  server.on("error", (error: NodeJS.ErrnoException) => {
    if (error.code === "EADDRINUSE") {
      const nextPort = port + 1;
      // eslint-disable-next-line no-console
      console.error(
        `Port ${port} is already in use. Stop the existing process or run PowerShell: $env:PORT=${nextPort}; npm run dev`
      );
      process.exit(1);
    }

    // eslint-disable-next-line no-console
    console.error("Failed to start API server:", error);
    process.exit(1);
  });
}
