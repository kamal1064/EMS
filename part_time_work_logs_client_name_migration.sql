-- Adds the client-aware part-time work log table requested by the app.
-- Run this in the Supabase SQL Editor for existing projects.

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

ALTER TABLE part_time_work_logs DISABLE ROW LEVEL SECURITY;

GRANT SELECT, INSERT, UPDATE, DELETE ON part_time_work_logs TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE part_time_work_logs_id_seq TO anon, authenticated;
