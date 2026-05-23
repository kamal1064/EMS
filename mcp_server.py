"""
Employee Management System (EMS) MCP Server
============================================
Exposes EMS MongoDB database operations as secure tools for AI agents.
Compatible with Claude Desktop, Cursor, and standard MCP clients.
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv

# Load environment configuration
load_dotenv()

try:
    from fastmcp import FastMCP
    from pymongo import MongoClient
    from bson.objectid import ObjectId
except ImportError:
    print("[ERROR] Required packages not yet installed. Please run: pip install mcp fastmcp pymongo[srv] python-dotenv")
    sys.exit(1)

# Initialize MCP server
mcp = FastMCP("EMS-MongoDB-Assistant")

# Connect to MongoDB
mongo_uri = os.environ.get('MONGO_URI')
if not mongo_uri:
    print("[ERROR] MONGO_URI is not set in environment or .env file.")
    sys.exit(1)

try:
    mongo_client = MongoClient(mongo_uri)
    mongo_client.admin.command('ping')
    db = mongo_client.get_default_database()
except Exception as e:
    try:
        db = mongo_client['ems_db']
    except Exception:
        print(f"[ERROR] Failed to establish MongoDB connection: {e}")
        sys.exit(1)


# Helper: Get user by email or username
def get_user(identifier: str):
    identifier = identifier.strip().lower()
    return db.users.find_one({"$or": [{"email": identifier}, {"username": identifier}]})


@mcp.tool()
def get_employees(user_identifier: str) -> str:
    """
    Retrieve the full roster of employees for a specific user (by email or username).
    """
    user = get_user(user_identifier)
    if not user:
        return f"User matching '{user_identifier}' not found."

    employees = list(db.employees.find({"user_id": user['_id']}).sort("name", 1))
    if not employees:
        return f"No employees registered under user '{user_identifier}'."

    output = [f"=== Employees for {user['username']} ==="]
    for e in employees:
        output.append(
            f"- ID: {e['_id']}\n"
            f"  Name: {e.get('name')}\n"
            f"  Department: {e.get('department', 'N/A')}\n"
            f"  Role: {e.get('role', 'N/A')}\n"
            f"  Salary: ${e.get('salary', 0):,.2f}\n"
            f"  Phone: {e.get('phone', 'N/A')}\n"
            f"  Age: {e.get('age', 'N/A')}\n"
            f"  Leaves: {e.get('leaves', 0)}\n"
            f"  Working Hours/Week: {e.get('working_hours', 40.0)}"
        )
    return "\n\n".join(output)


@mcp.tool()
def add_new_employee(
    user_identifier: str,
    name: str,
    salary: float,
    department: str = "Staff",
    role: str = "Employee",
    phone: str = "",
    age: int = 30,
    working_hours: float = 40.0
) -> str:
    """
    Add a new employee to the user's roster.
    """
    if not name.strip():
        return "Error: Employee name cannot be empty."
    if salary < 0:
        return "Error: Salary must be non-negative."

    user = get_user(user_identifier)
    if not user:
        return f"User matching '{user_identifier}' not found."

    emp_doc = {
        "name": name.strip(),
        "phone": phone.strip(),
        "age": age,
        "gender": "Other",
        "salary": salary,
        "leaves": 0,
        "working_hours": working_hours,
        "department": department.strip(),
        "role": role.strip(),
        "user_id": user['_id'],
        "created_at": datetime.now().isoformat()
    }
    result = db.employees.insert_one(emp_doc)
    return f"Success: Added employee '{name}' to roster with ID: {result.inserted_id}."


@mcp.tool()
def mark_attendance(
    employee_name: str,
    user_identifier: str,
    status: str,
    date_str: str = ""
) -> str:
    """
    Mark an employee's attendance status (Present or Absent) for a specific date (YYYY-MM-DD).
    If date_str is omitted, today's date is used.
    """
    status = status.strip().capitalize()
    if status not in ["Present", "Absent"]:
        return "Error: Status must be 'Present' or 'Absent'."

    if not date_str:
        date_str = datetime.now().strftime('%Y-%m-%d')

    user = get_user(user_identifier)
    if not user:
        return f"User matching '{user_identifier}' not found."

    # Find employee by name
    emp = db.employees.find_one({"name": {"$regex": f"^{employee_name.strip()}$", "$options": "i"}, "user_id": user['_id']})
    if not emp:
        return f"Employee '{employee_name}' not found under user '{user_identifier}'."

    # Update or insert attendance
    db.attendance.update_one(
        {"emp_id": emp['_id'], "date": date_str},
        {"$set": {"status": status}},
        upsert=True
    )
    return f"Success: Marked {emp['name']} as '{status}' for {date_str}."


@mcp.tool()
def get_part_time_workforce(user_identifier: str) -> str:
    """
    Retrieve all registered part-time workers and their work logs.
    """
    user = get_user(user_identifier)
    if not user:
        return f"User matching '{user_identifier}' not found."

    workers = list(db.part_time_workers.find({"user_id": user['_id']}).sort("name", 1))
    if not workers:
        return f"No part-time workers registered under user '{user_identifier}'."

    worker_names = {str(w['_id']): w['name'] for w in workers}
    worker_ids = list(worker_names.keys())

    logs = list(db.part_time_work_logs.find({"worker_id": {"$in": [ObjectId(wid) for wid in worker_ids]}}).sort("_id", -1))

    output = ["=== Part-Time Workforce ==="]
    for w in workers:
        output.append(f"- Worker: {w['name']} (ID: {w['_id']})")

    output.append("\n=== Recent Part-Time Logs ===")
    if not logs:
        output.append("(No logs registered)")
    for l in logs:
        w_name = worker_names.get(str(l['worker_id']), "Unknown")
        output.append(
            f"- Date: {l.get('working_date')}\n"
            f"  Worker: {w_name}\n"
            f"  Client: {l.get('client_name')}\n"
            f"  Location: {l.get('delivery_location')}\n"
            f"  Productivity: {l.get('slab_quantity', 0)} slabs @ ${l.get('slab_price', 0):,.2f}/slab\n"
            f"  Total Payout: ${l.get('total_price', 0):,.2f}\n"
            f"  Advance Paid: ${l.get('advance_paid', 0):,.2f}\n"
            f"  Remaining: ${l.get('remaining_balance', 0):,.2f}\n"
            f"  Payment: {l.get('payment_status')}"
        )
    return "\n\n".join(output)


if __name__ == '__main__':
    # Start the FastMCP server (standard stdio protocol)
    mcp.run()
