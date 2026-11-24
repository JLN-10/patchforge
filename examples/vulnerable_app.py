import os
import sqlite3

# VULNERABILITY 1: Hardcoded Secret
API_KEY = "live_sk_secret_9948271048291038"

def run_backup(backup_name: str):
    # VULNERABILITY 2: Command Injection
    cmd = f"tar -czf {backup_name}.tar.gz /data"
    os.system(cmd)

def get_user_profile(user_id: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABILITY 3: SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()
