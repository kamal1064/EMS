-- =============================================
-- Employee Management System - Supabase Schema
-- Run this in your Supabase SQL Editor
-- =============================================

-- Users table (owners/admins)
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    otp_secret TEXT,
    otp_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Employees table
CREATE TABLE IF NOT EXISTS employees (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT,
    age INTEGER,
    gender TEXT,
    salary REAL,
    leaves INTEGER DEFAULT 0,
    working_hours REAL DEFAULT 40,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Attendance table
CREATE TABLE IF NOT EXISTS attendance (
    id BIGSERIAL PRIMARY KEY,
    emp_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    date TEXT NOT NULL,
    status TEXT NOT NULL,
    UNIQUE(emp_id, date)
);

-- Salary records table
CREATE TABLE IF NOT EXISTS salary_records (
    id BIGSERIAL PRIMARY KEY,
    emp_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    month TEXT NOT NULL,
    present_days INTEGER DEFAULT 0,
    total_salary REAL DEFAULT 0,
    advance_amount_paid REAL DEFAULT 0,
    advance_paid_at TEXT,
    payment_status TEXT DEFAULT 'Unpaid',
    paid_at TEXT
);

-- Part-time work logs table
CREATE TABLE IF NOT EXISTS part_time_work_logs (
    id BIGSERIAL PRIMARY KEY,
    worker_id BIGINT NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
    client_name TEXT NOT NULL,
    working_date TEXT NOT NULL,
    slab_quantity INTEGER NOT NULL,
    slab_price REAL NOT NULL,
    total_price REAL NOT NULL,
    delivery_location TEXT NOT NULL,
    advance_paid REAL DEFAULT 0,
    payment_status TEXT DEFAULT 'Unpaid',
    remaining_balance REAL DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_part_time_work_logs_worker_id
    ON part_time_work_logs(worker_id);

CREATE INDEX IF NOT EXISTS idx_part_time_work_logs_client_name
    ON part_time_work_logs(client_name);

CREATE INDEX IF NOT EXISTS idx_part_time_work_logs_working_date
    ON part_time_work_logs(working_date);

-- Legacy table retained for older installations that still reference it.
CREATE TABLE IF NOT EXISTS part_time_employee (
    id BIGSERIAL PRIMARY KEY,
    employee_name TEXT NOT NULL,
    client_name TEXT NOT NULL DEFAULT 'Unassigned',
    working_date TEXT NOT NULL,
    slab_quantity INTEGER NOT NULL,
    slab_price REAL NOT NULL,
    total_price REAL NOT NULL,
    delivery_location TEXT NOT NULL,
    advance_amount_paid REAL DEFAULT 0,
    advance_paid_at TEXT,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE
);

-- Disable Row Level Security (app handles auth via sessions)
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE employees DISABLE ROW LEVEL SECURITY;
ALTER TABLE attendance DISABLE ROW LEVEL SECURITY;
ALTER TABLE salary_records DISABLE ROW LEVEL SECURITY;
ALTER TABLE part_time_work_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE part_time_employee DISABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON employees TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE employees_id_seq TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON attendance TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE attendance_id_seq TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON salary_records TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE salary_records_id_seq TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON part_time_work_logs TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE part_time_work_logs_id_seq TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON part_time_employee TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE part_time_employee_id_seq TO anon, authenticated;

