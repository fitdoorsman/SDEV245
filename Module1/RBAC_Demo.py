# Simple Role-Based Access Control (RBAC) Example
# Author: Jason Hollin

# Step 1: Hardcoded login simulation
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "user": {"password": "user123", "role": "user"}
}

# Step 2: Role-based actions
def admin_dashboard():
    return "Welcome to the Admin Dashboard. You can manage users and settings."

def user_dashboard():
    return "Welcome to the User Dashboard. You can view your profile and basic info."

# Step 3: Login prompt
print("=== Login Simulation ===")
username = input("Enter username: ")
password = input("Enter password: ")

if username in users and users[username]["password"] == password:
    role = users[username]["role"]
    print(f"\nLogin successful! Your role is: {role.upper()}")

    # Step 4: Access control
    if role == "admin":
        print(admin_dashboard())
    elif role == "user":
        print(user_dashboard())
else:
    print("\nLogin failed! Invalid username or password")
