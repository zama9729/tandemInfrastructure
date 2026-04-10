create extension if not exists "pgcrypto";

create table if not exists candidates (
  id uuid primary key default gen_random_uuid(),
  first_name text not null,
  last_name text not null,
  name text not null,
  email text unique not null,
  phone text,
  dob date,
  city text,
  qualification text,
  department text,
  password_hash text not null,
  cv text,
  documents jsonb default '[]'::jsonb,
  registered_at timestamptz default now()
);

create table if not exists applications (
  id uuid primary key default gen_random_uuid(),
  candidate_id uuid not null references candidates(id) on delete cascade,
  job_key text not null,
  job_title text not null,
  job_dept text,
  qualification text,
  experience text,
  location text,
  note text,
  cv_file text,
  status text default 'Under Review',
  applied_at timestamptz default now(),
  unique(candidate_id, job_key)
);

create table if not exists enquiries (
  id uuid primary key default gen_random_uuid(),
  first_name text not null,
  last_name text not null,
  email text not null,
  phone text,
  service text,
  details text,
  created_at timestamptz default now()
);

create table if not exists jobs (
  id uuid primary key default gen_random_uuid(),
  job_key text unique not null,
  title text not null,
  dept text,
  dept_icon text,
  tags jsonb default '[]'::jsonb,
  description text,
  requirements jsonb default '[]'::jsonb,
  qualification text,
  experience text,
  location text,
  status text default 'Open',
  is_active boolean default true,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- This app uses a custom JWT and server-side Supabase client.
-- Keep RLS disabled to avoid anon inserts being blocked.
alter table candidates disable row level security;
alter table applications disable row level security;
alter table enquiries disable row level security;
alter table jobs disable row level security;

create index if not exists idx_candidates_email on candidates (email);
create index if not exists idx_applications_candidate_id on applications (candidate_id);
create index if not exists idx_applications_job_key on applications (job_key);
create index if not exists idx_enquiries_email on enquiries (email);
create index if not exists idx_jobs_key on jobs (job_key);
create index if not exists idx_jobs_active on jobs (is_active);

-- CMS
create table if not exists cms_pages (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  title text,
  is_active boolean default true,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists cms_sections (
  id uuid primary key default gen_random_uuid(),
  page_id uuid references cms_pages(id) on delete cascade,
  key text not null,
  title text,
  subtitle text,
  body text,
  sort_order int default 0,
  is_active boolean default true,
  settings jsonb default '{}'::jsonb,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists cms_items (
  id uuid primary key default gen_random_uuid(),
  section_id uuid references cms_sections(id) on delete cascade,
  title text,
  subtitle text,
  body text,
  image_url text,
  link_url text,
  link_label text,
  tags jsonb default '[]'::jsonb,
  meta jsonb default '{}'::jsonb,
  sort_order int default 0,
  is_active boolean default true,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists cms_settings (
  id uuid primary key default gen_random_uuid(),
  key text unique not null,
  value text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

alter table cms_pages disable row level security;
alter table cms_sections disable row level security;
alter table cms_items disable row level security;
alter table cms_settings disable row level security;

create index if not exists idx_cms_sections_page on cms_sections (page_id);
create index if not exists idx_cms_sections_key on cms_sections (key);
create index if not exists idx_cms_items_section on cms_items (section_id);
create index if not exists idx_cms_pages_slug on cms_pages (slug);

-- Reset data (use before re-seeding)
truncate table
  applications,
  candidates,
  enquiries,
  jobs,
  cms_items,
  cms_sections,
  cms_pages,
  cms_settings
restart identity cascade;

insert into cms_pages (slug, title)
values
  ('home','Home'),
  ('careers','Careers'),
  ('candidate-auth','Candidate Auth'),
  ('candidate-dashboard','Candidate Dashboard'),
  ('admin','Admin')
on conflict (slug) do nothing;

insert into cms_settings (key, value)
values
  ('brand_name','Tandem Infra Services'),
  ('brand_subtitle','Infrastructure & Construction'),
  ('contact_phone','+91 94297 39999'),
  ('contact_email','info@tandeminfra.com'),
  ('contact_address','Flat 302, Sri Chakra Raja Nilayam, Sangeeth Nagar, Kukatpally, Hyderabad, Telangana PIN - 500072')
on conflict (key) do nothing;

-- Home page starter content
insert into cms_sections (page_id, key, title, subtitle, body, sort_order)
select p.id, s.key, s.title, s.subtitle, s.body, s.sort_order
from cms_pages p
join (values
  ('hero','Building<br><em>Strong</em><br>Foundations','Established 2026 - Infrastructure Excellence','Tandem Infra Services delivers end-to-end construction and infrastructure solutions - from structural engineering and project management to quality assurance and sustainable building.',0),
  ('ticker','Ticker',null,null,1),
  ('about','<strong>Tandem Infra Services</strong> -<br><em>Infrastructure Built Right</em>','Who We Are','<p class="about-text">Tandem Infra Services is a dynamic, new-generation infrastructure and construction company founded in 2026. With a focused team of 9 professionals, we bring sharp expertise and fresh energy to every project we take on.</p><p class="about-text">We deliver comprehensive infrastructure solutions - structural engineering, project management, quality assurance, BIM services, and sustainable construction - with a personal, hands-on client approach that larger firms simply cannot match.</p>',2),
  ('services','<strong>Our</strong> <em>Services</em>','What We Do','End-to-end construction and infrastructure services delivered by a focused team of certified specialists.',3),
  ('why','<strong>Small Team,</strong><br><em>Serious Results</em>','Why Tandem Infra','We are a focused, expert-driven team. Every project gets personal senior attention - no hand-offs to junior staff, no compromises on quality or safety.',4),
  ('projects','<strong>Our</strong> <em>Work</em>','Portfolio',null,5),
  ('process','<strong>Our</strong> <em>Process</em>','How We Work','A transparent, four-step methodology ensuring measurable quality at every milestone - from first site visit to final handover and support.',6),
  ('testimonials','<strong>Client</strong> <em>Voices</em>','What Clients Say',null,7),
  ('clients',null,'Serving Clients Across India',null,8),
  ('contact','<strong>Let''s Build</strong><br><em>Together</em>','Get In Touch','Ready to discuss your project? Our team responds to every enquiry personally. No automated responses - just real people who care about your build.',9)
) as s(key,title,subtitle,body,sort_order)
on p.slug = 'home'
where not exists (
  select 1 from cms_sections cs where cs.page_id = p.id and cs.key = s.key
);

update cms_sections set
  title = 'Building<br><em>Strong</em><br>Foundations',
  subtitle = 'Established 2026 - Infrastructure Excellence',
  body = 'Tandem Infra Services delivers end-to-end construction and infrastructure solutions - from structural engineering and project management to quality assurance and sustainable building.'
where key = 'hero' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Tandem Infra Services</strong> -<br><em>Infrastructure Built Right</em>',
  subtitle = 'Who We Are',
  body = '<p class="about-text">Tandem Infra Services is a dynamic, new-generation infrastructure and construction company founded in 2026. With a focused team of 9 professionals, we bring sharp expertise and fresh energy to every project we take on.</p><p class="about-text">We deliver comprehensive infrastructure solutions - structural engineering, project management, quality assurance, BIM services, and sustainable construction - with a personal, hands-on client approach that larger firms simply cannot match.</p>'
where key = 'about' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Our</strong> <em>Services</em>',
  subtitle = 'What We Do',
  body = 'End-to-end construction and infrastructure services delivered by a focused team of certified specialists.'
where key = 'services' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Small Team,</strong><br><em>Serious Results</em>',
  subtitle = 'Why Tandem Infra',
  body = 'We are a focused, expert-driven team. Every project gets personal senior attention - no hand-offs to junior staff, no compromises on quality or safety.'
where key = 'why' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Our</strong> <em>Work</em>',
  subtitle = 'Portfolio'
where key = 'projects' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Our</strong> <em>Process</em>',
  subtitle = 'How We Work',
  body = 'A transparent, four-step methodology ensuring measurable quality at every milestone - from first site visit to final handover and support.'
where key = 'process' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Client</strong> <em>Voices</em>',
  subtitle = 'What Clients Say'
where key = 'testimonials' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  subtitle = 'Serving Clients Across India'
where key = 'clients' and page_id in (select id from cms_pages where slug = 'home');

update cms_sections set
  title = '<strong>Let''s Build</strong><br><em>Together</em>',
  subtitle = 'Get In Touch',
  body = 'Ready to discuss your project? Our team responds to every enquiry personally. No automated responses - just real people who care about your build.'
where key = 'contact' and page_id in (select id from cms_pages where slug = 'home');

update cms_settings set value = 'tandeminfraservices@gmail.com' where key = 'contact_email';
update cms_settings set value = 'Flat 302, Sri Chakra Raja Nilayam, Sangeeth Nagar, Kukatpally, Hyderabad, Telangana PIN - 500072' where key = 'contact_address';
update cms_sections
set settings = coalesce(settings, '{}'::jsonb) || jsonb_build_object(
  'branchesHtml',
  '<h3>Telangana Branch</h3><address>Flat 302, Sri Chakra Raja Nilayam, Sangeeth Nagar, Kukatpally, Hyderabad, Telangana PIN - 500072</address><h3>Andhra Pradesh Branch</h3><address>Flat number 05, Veera Apartment, Dr/No 59A-21/3-2/13B, Vijaynagar Colony, Near Don Bosco School, Vijayawada, Andhra Pradesh PIN - 520008</address><h3>Maharashtra Branch</h3><address>Flat number B8, Park View Housing Society, Kingsway Road, Nagpur, Maharastra PIN - 440001</address>'
)
where key = 'contact' and page_id in (select id from cms_pages where slug = 'home');

delete from cms_items
where section_id in (
  select id from cms_sections
  where page_id in (select id from cms_pages where slug = 'home')
    and key in ('hero','about','services','why','projects','process','ticker','testimonials','clients')
);

-- Hero slide (single image to match uploaded HTML)
insert into cms_items (section_id, image_url, sort_order)
select cs.id, i.image_url, i.sort_order
from cms_sections cs
join (values
  ('https://images.unsplash.com/photo-1504307651254-35680f356dfd?w=1800&auto=format&fit=crop',0)
) as i(image_url,sort_order)
on cs.key = 'hero'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Ticker items
insert into cms_items (section_id, title, sort_order)
select cs.id, i.title, i.sort_order
from cms_sections cs
join (values
  ('Project Management',0),
  ('Structural Engineering',1),
  ('BIM Solutions',2),
  ('Quality Assurance',3),
  ('Infrastructure Planning',4),
  ('Sustainable Construction',5)
) as i(title,sort_order)
on cs.key = 'ticker'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- About pillars
insert into cms_items (section_id, title, body, sort_order)
select cs.id, i.title, i.body, i.sort_order
from cms_sections cs
join (values
  ('Structural Integrity','Every structure built to exceed code and expectations.',0),
  ('Safety First','Non-negotiable protocols across every phase of work.',1),
  ('Sustainability','Green building at the core of every decision we make.',2),
  ('Smart Infrastructure','IoT-ready systems for tomorrow''s built environment.',3)
) as i(title,body,sort_order)
on cs.key = 'about'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Services
insert into cms_items (section_id, title, body, link_url, link_label, sort_order)
select cs.id, i.title, i.body, i.link_url, i.link_label, i.sort_order
from cms_sections cs
join (values
  ('Project Management','Full-lifecycle delivery from feasibility through handover - schedules, budgets, stakeholder coordination and expert supervision at every stage.','#contact','Enquire Now ->',0),
  ('Structural Engineering & Inspection','Structural analysis, load testing, third-party inspections and IS code compliance for commercial, industrial and residential projects.','#contact','Enquire Now ->',1),
  ('Building Information Modeling','Advanced BIM for 3D coordination, 4D scheduling, clash detection and real-time collaboration across all architecture and engineering disciplines.','#contact','Enquire Now ->',2),
  ('Quality Assurance & Control','Rigorous QA/QC protocols, material testing, construction audits and ISO-aligned documentation for defect-free project delivery.','#contact','Enquire Now ->',3),
  ('Infrastructure Planning','Strategic planning for roads, bridges, utilities and civic infrastructure integrating communication networks, data systems and IoT resilience.','#contact','Enquire Now ->',4),
  ('Sustainable Construction','Green building solutions targeting LEED, GRIHA and IGBC certifications - passive design, renewable energy integration, smart water systems.','#contact','Enquire Now ->',5)
) as i(title,body,link_url,link_label,sort_order)
on cs.key = 'services'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Why items (with stats)
insert into cms_items (section_id, title, body, meta, sort_order)
select cs.id, i.title, i.body, i.meta, i.sort_order
from cms_sections cs
join (values
  ('Expert Professionals','A compact, highly specialised team delivering focused expertise on every single project we take on.','{"num":"9"}'::jsonb,0),
  ('Senior-Led Projects','Every engagement personally led by experienced professionals - guaranteed senior attention from day one.','{"num":"100%"}'::jsonb,1),
  ('Core Service Lines','Comprehensive infrastructure capabilities under one roof, eliminating coordination gaps between multiple consultants.','{"num":"6+"}'::jsonb,2),
  ('Compromise on Safety','Safety is non-negotiable. Rigorous HSSE protocols are followed across every project, every single day.','{"num":"0"}'::jsonb,3),
  ('Built for Today','Founded in 2026 - we bring fresh perspectives, modern tools and current best practices to every challenge.','{"num":"2026"}'::jsonb,4),
  ('Site Support Available','On-call project support available around the clock during critical construction and delivery phases.','{"num":"24/7"}'::jsonb,5)
) as i(title,body,meta,sort_order)
on cs.key = 'why'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Projects
insert into cms_items (section_id, title, subtitle, body, image_url, sort_order)
select cs.id, i.title, i.subtitle, i.body, i.image_url, i.sort_order
from cms_sections cs
join (values
  ('Urban Road Infrastructure - Assessment','Infrastructure','India','https://images.unsplash.com/photo-1486325212027-8081e485255e?w=900&auto=format&fit=crop',0),
  ('Industrial Facility - Structural Review','Industrial','India','https://images.unsplash.com/photo-1541888946425-d81bb19240f5?w=600&auto=format&fit=crop',1),
  ('Commercial Complex - Project Management','Commercial','India','https://images.unsplash.com/photo-1504307651254-35680f356dfd?w=600&auto=format&fit=crop',2),
  ('Township Infrastructure - Feasibility Study','Planning','India','https://images.unsplash.com/photo-1477959858617-67f85cf4f1df?w=900&auto=format&fit=crop',3)
) as i(title,subtitle,body,image_url,sort_order)
on cs.key = 'projects'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Process
insert into cms_items (section_id, title, body, sort_order)
select cs.id, i.title, i.body, i.sort_order
from cms_sections cs
join (values
  ('Discovery & Feasibility','Site analysis, geotechnical review, regulatory study and detailed feasibility to scope the project correctly from the start.',0),
  ('Design & Engineering','Architectural and structural design, BIM modelling, MEP coordination and value engineering for optimised performance.',1),
  ('Construction & Supervision','Expert on-site management with daily QC checks, safety audits and real-time progress reporting to all stakeholders.',2),
  ('Handover & Support','Complete documentation, commissioning tests, client training and post-handover technical support included in every engagement.',3)
) as i(title,body,sort_order)
on cs.key = 'process'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Testimonials
insert into cms_items (section_id, title, subtitle, body, image_url, sort_order)
select cs.id, i.title, i.subtitle, i.body, i.image_url, i.sort_order
from cms_sections cs
join (values
  ('Rakesh Verma','Director, Verma Builders','A team that genuinely cares about the outcome. Their structural review was meticulous and delivered faster than any firm we had worked with before.','https://i.pravatar.cc/100?img=11',0),
  ('Priya Desai','Operations Head, Greenfield Realty','Exceptional project management. Small team, huge capability - they handled our site with the same professionalism as firms three times their size.','https://i.pravatar.cc/100?img=33',1),
  ('Arjun Shah','CEO, Shah Group','Their QA documentation and audit trails gave our investors the confidence they needed. Highly recommend Tandem Infra for any serious construction project.','https://i.pravatar.cc/100?img=55',2),
  ('Meena Krishnan','Head of Projects, HealthCare Infra','BIM coordination saved us weeks of rework and significantly reduced material waste on our hospital project. Modern tools, professional delivery.','https://i.pravatar.cc/100?img=22',3)
) as i(title,subtitle,body,image_url,sort_order)
on cs.key = 'testimonials'
where cs.page_id in (select id from cms_pages where slug = 'home');

-- Clients
insert into cms_items (section_id, title, sort_order)
select cs.id, i.title, i.sort_order
from cms_sections cs
join (values
  ('CLIENTS',0),
  ('-',1),
  ('IN PROGRESS',2),
  ('-',3),
  ('EST. 2026',4)
) as i(title,sort_order)
on cs.key = 'clients'
where cs.page_id in (select id from cms_pages where slug = 'home');








