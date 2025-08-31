# Module 1 - Simple Role-Based Access Control (RBAC)
# Author: Jason Hollin

# ---- 1) Login simulation (hardcoded users) ----
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user":  {"password": "user123",  "role": "user"}
}

# ---- 2) Protected actions/endpoints ----
def view_admin_reports():
    return "[ADMIN REPORTS] Quarterly financials and user management tools."

def view_user_profile():
    return "[USER PROFILE] Your settings, preferences, and recent activity."

# Simple authorization check
def authorize(required_role, current_role):
    return required_role == current_role

print("=== Login Simulation ===")
username = input("Username: ").strip()
password = input("Password: ").strip()

if username in users and users[username]["password"] == password:
    role = users[username]["role"]
    print(f"\nLogin successful! Your role is: {role.upper()}")

    # ---- 3) Let the user attempt both endpoints ----
    while True:
        print("\nChoose an action:")
        print("  1) View ADMIN reports   (admin-only)")
        print("  2) View USER profile    (user-only)")
        print("  3) Exit")
        choice = input("Enter 1, 2, or 3: ").strip()

        if choice == "1":
            if authorize("admin", role):
                print(view_admin_reports())
            else:
                print("ACCESS DENIED: admin role required")
        elif choice == "2":
            if authorize("user", role):
                print(view_user_profile())
            else:
                print("ACCESS DENIED: user role required")
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Try again")
else:
    print("\nLogin failed! Invalid username or password")
