export type Candidate = {
  id: string;
  first_name: string;
  last_name: string;
  name: string;
  email: string;
  phone: string | null;
  dob: string | null;
  city: string | null;
  qualification: string | null;
  department: string | null;
  cv: string | null;
  documents: Array<{ type: string; filename: string; uploadedAt: string }>;
  registered_at: string;
};

export type Application = {
  id: string;
  candidate_id: string;
  job_key: string;
  job_title: string;
  job_dept: string | null;
  qualification: string | null;
  experience: string | null;
  location: string | null;
  note: string | null;
  cv_file: string | null;
  status: string | null;
  applied_at: string;
};
