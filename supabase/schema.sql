-- PTUT Hub: database + security rules (Supabase / PostgreSQL)
-- How to run: Supabase dashboard > SQL Editor > New query > paste this whole file > Run.

create extension if not exists pgcrypto;

create type user_role     as enum ('student','cr','admin');
create type ann_category  as enum ('university','department','program','semester','section','important');
create type task_priority as enum ('low','medium','high');
create type publish_state as enum ('draft','published');

-- ========== Academic structure (admin-editable) ==========
create table departments (id uuid primary key default gen_random_uuid(), name text not null unique);
create table programs    (id uuid primary key default gen_random_uuid(), department_id uuid not null references departments on delete cascade, name text not null, unique (department_id, name));
create table semesters   (id uuid primary key default gen_random_uuid(), program_id uuid not null references programs on delete cascade, number int not null check (number between 1 and 12), unique (program_id, number));
create table sections    (id uuid primary key default gen_random_uuid(), semester_id uuid not null references semesters on delete cascade, name text not null, unique (semester_id, name));
create table teachers    (id uuid primary key default gen_random_uuid(), full_name text not null, email text);
create table rooms       (id uuid primary key default gen_random_uuid(), name text not null unique, building text);
create table subjects    (id uuid primary key default gen_random_uuid(), program_id uuid not null references programs on delete cascade, code text, name text not null, color text not null default '#0d5c36');

-- ========== Users ==========
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  student_id text unique,
  role user_role not null default 'student',
  section_id uuid references sections on delete set null,
  onboarded boolean not null default false,
  created_at timestamptz not null default now()
);

-- ========== Timetable, exams, announcements ==========
create table timetable_entries (
  id uuid primary key default gen_random_uuid(),
  section_id uuid not null references sections on delete cascade,
  subject_id uuid not null references subjects on delete restrict,
  teacher_id uuid references teachers on delete set null,
  room_id uuid references rooms on delete set null,
  day smallint not null check (day between 0 and 5),      -- 0 = Monday
  start_time time not null,
  end_time time not null,
  cancelled boolean not null default false,
  status publish_state not null default 'draft',
  check (end_time > start_time)
);
create table exams (
  id uuid primary key default gen_random_uuid(),
  section_id uuid not null references sections on delete cascade,
  subject_id uuid references subjects on delete set null,
  title text not null,
  exam_date date not null,
  start_time time not null,
  room_id uuid references rooms on delete set null,
  status publish_state not null default 'draft'
);
create table announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  category ann_category not null default 'university',
  important boolean not null default false,
  -- leave all audience columns empty = everyone
  audience_department_id uuid references departments on delete cascade,
  audience_program_id    uuid references programs on delete cascade,
  audience_semester_id   uuid references semesters on delete cascade,
  audience_section_id    uuid references sections on delete cascade,
  author_id uuid references profiles on delete set null default auth.uid(),
  publish_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

-- ========== Personal data ==========
create table tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles on delete cascade default auth.uid(),
  title text not null, subject text, category text not null default 'assignment',
  priority task_priority not null default 'medium', due_date date, notes text,
  progress int not null default 0 check (progress between 0 and 100),
  done boolean not null default false, created_at timestamptz not null default now()
);
create table exam_prep (
  user_id uuid not null references profiles on delete cascade default auth.uid(),
  exam_id uuid not null references exams on delete cascade,
  progress int not null default 0 check (progress between 0 and 100),
  primary key (user_id, exam_id)
);
create table notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles on delete cascade,
  kind text not null, title text not null, body text,
  read boolean not null default false, created_at timestamptz not null default now()
);

-- ========== Helper functions (who is the current user?) ==========
create function is_admin() returns boolean language sql stable security definer set search_path = public as
$$ select coalesce((select role = 'admin' from profiles where id = auth.uid()), false) $$;
create function is_cr() returns boolean language sql stable security definer set search_path = public as
$$ select coalesce((select role = 'cr' from profiles where id = auth.uid()), false) $$;
create function my_section() returns uuid language sql stable security definer set search_path = public as
$$ select section_id from profiles where id = auth.uid() $$;
create function my_semester() returns uuid language sql stable security definer set search_path = public as
$$ select s.semester_id from profiles p join sections s on s.id = p.section_id where p.id = auth.uid() $$;
create function my_program() returns uuid language sql stable security definer set search_path = public as
$$ select sm.program_id from profiles p join sections s on s.id = p.section_id join semesters sm on sm.id = s.semester_id where p.id = auth.uid() $$;
create function my_department() returns uuid language sql stable security definer set search_path = public as
$$ select pr.department_id from profiles p join sections s on s.id = p.section_id join semesters sm on sm.id = s.semester_id join programs pr on pr.id = sm.program_id where p.id = auth.uid() $$;

-- New sign-up => create a profile automatically
create function handle_new_user() returns trigger language plpgsql security definer set search_path = public as
$$ begin
  insert into profiles (id, full_name) values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

-- Only an admin can change roles
create function block_role_change() returns trigger language plpgsql as
$$ begin
  if new.role is distinct from old.role and not is_admin() then raise exception 'Only an admin can change roles'; end if;
  return new;
end $$;
create trigger profiles_role_guard before update on profiles for each row execute function block_role_change();

-- ========== Row-level security ==========
alter table departments, programs, semesters, sections, teachers, rooms, subjects,
            profiles, timetable_entries, exams, announcements, tasks, exam_prep, notifications
  enable row level security;

-- Academic structure: everyone signed in can read, only admins can change
do $$ declare t text; begin
  foreach t in array array['departments','programs','semesters','sections','teachers','rooms','subjects'] loop
    execute format('create policy "%1$s read" on %1$s for select to authenticated using (true)', t);
    execute format('create policy "%1$s admin write" on %1$s for all to authenticated using (is_admin()) with check (is_admin())', t);
  end loop;
end $$;

-- Profiles
create policy "profile read"   on profiles for select to authenticated using (id = auth.uid() or is_admin());
create policy "profile update" on profiles for update to authenticated using (id = auth.uid() or is_admin()) with check (id = auth.uid() or is_admin());

-- Timetable and exams: students see only their own published section; admins manage all
create policy "timetable read"  on timetable_entries for select to authenticated using (is_admin() or (status = 'published' and section_id = my_section()));
create policy "timetable admin" on timetable_entries for all to authenticated using (is_admin()) with check (is_admin());
create policy "exams read"      on exams for select to authenticated using (is_admin() or (status = 'published' and section_id = my_section()));
create policy "exams admin"     on exams for all to authenticated using (is_admin()) with check (is_admin());

-- Announcements: audience-aware reading; CRs may post only to their own section
create policy "announcements read" on announcements for select to authenticated using (
  is_admin() or (publish_at <= now() and (
    (audience_department_id is null and audience_program_id is null and audience_semester_id is null and audience_section_id is null)
    or audience_section_id = my_section() or audience_semester_id = my_semester()
    or audience_program_id = my_program() or audience_department_id = my_department()))
);
create policy "announcements admin" on announcements for all to authenticated using (is_admin()) with check (is_admin());
create policy "cr post" on announcements for insert to authenticated with check (
  is_cr() and audience_section_id = my_section() and audience_department_id is null
  and audience_program_id is null and audience_semester_id is null and author_id = auth.uid());
create policy "cr edit own"   on announcements for update to authenticated using (is_cr() and author_id = auth.uid()) with check (is_cr() and audience_section_id = my_section());
create policy "cr delete own" on announcements for delete to authenticated using (is_cr() and author_id = auth.uid());

-- Personal data: only the owner
create policy "own tasks"         on tasks         for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own exam prep"     on exam_prep     for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own notifications" on notifications for select to authenticated using (user_id = auth.uid());
create policy "mark read"         on notifications for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "admin notify"      on notifications for insert to authenticated with check (is_admin());

-- ========== Starter data (admin can edit all of this later) ==========
insert into departments (name) values ('Computer Science'), ('Electrical Engineering Technology'), ('Automotive Engineering Technology');
insert into programs (department_id, name)
  select id, 'BS Computer Science' from departments where name = 'Computer Science'
  union all select id, 'BS Information Technology' from departments where name = 'Computer Science'
  union all select id, 'BSc Electrical Engineering Technology' from departments where name = 'Electrical Engineering Technology'
  union all select id, 'BSc Automotive Engineering Technology' from departments where name = 'Automotive Engineering Technology';
insert into semesters (program_id, number) select p.id, n from programs p, generate_series(1, 8) n;
insert into sections (semester_id, name) select s.id, x from semesters s, unnest(array['A','B','C']) x;

-- ========== Make yourself the first admin (run AFTER you sign up in the app) ==========
-- update profiles set role = 'admin' where id = (select id from auth.users where email = 'YOUR_EMAIL_HERE');
