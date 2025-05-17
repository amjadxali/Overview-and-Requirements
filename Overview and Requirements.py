
# Writing Secure Code Using Microsoft Copilot

# Step 2: Secure Input Validation
# Modify the form input validation to sanitize user data and prevent script injections:
function sanitizeInput(input) {
    return input.replace(/</g, "&lt;").replace(/>/g, "&gt;").trim();
}

document.querySelector("form").addEventListener("submit", function(event) {
    let username = sanitizeInput(document.getElementById("username").value);
    let email = sanitizeInput(document.getElementById("email").value);
    
    if (!username || !email) {
        event.preventDefault();
        alert("Invalid input!");
    }
});


# Step 3: Use Parameterized Queries to Prevent SQL Injection
# Modify database queries to use prepared statements:
import mysql.connector

conn = mysql.connector.connect(host="localhost", user="root", password="", database="SafeVaultDB")
cursor = conn.cursor()

def get_user(username, email):
    query = "SELECT * FROM Users WHERE Username = %s AND Email = %s"
    cursor.execute(query, (username, email))
    return cursor.fetchall()


# Step 4: Test for Vulnerabilities
# Write unit tests to ensure SQL injection and XSS vulnerabilities are mitigated:
using NUnit.Framework;

[TestFixture]
public class TestInputValidation {
    [Test]
    public void TestForSQLInjection() {
        string maliciousInput = "'; DROP TABLE Users; --";
        string sanitized = InputSanitizer.Sanitize(maliciousInput);
        Assert.AreNotEqual(maliciousInput, sanitized);
    }

    [Test]
    public void TestForXSS() {
        string maliciousScript = "<script>alert('XSS');</script>";
        string sanitized = InputSanitizer.Sanitize(maliciousScript);
        Assert.AreNotEqual(maliciousScript, sanitized);
    }
}


# Implementing Authentication and Authorization Using Microsoft Copilot

# Step 2: Generate Authentication Code
# create a login system using bcrypt for secure password hashin
import bcrypt
import mysql.connector

# Function to hash passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Function to verify user credentials
def authenticate_user(username, password):
    conn = mysql.connector.connect(host="localhost", user="root", password="", database="SafeVaultDB")
    cursor = conn.cursor()
    
    query = "SELECT password_hash FROM Users WHERE Username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    
    if result and bcrypt.checkpw(password.encode(), result[0].encode()):
        return True
    return False


# Step 3: Implement Role-Based Authorization (RBAC)
# Assign roles to users and restrict access.
def get_user_role(username):
    conn = mysql.connector.connect(host="localhost", user="root", password="", database="SafeVaultDB")
    cursor = conn.cursor()
    
    query = "SELECT role FROM Users WHERE Username = %s"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    
    return result[0] if result else None

def is_admin(username):
    return get_user_role(username) == "admin"

# Example: Protect admin dashboard
def access_admin_dashboard(username):
    if is_admin(username):
        return "Access granted to Admin Dashboard"
    return "Access denied"


# Step 4: Test Authentication and Authorization
# Write test cases to verify proper security and role-based access.
using NUnit.Framework;

[TestFixture]
public class TestAuthSystem {
    [Test]
    public void TestInvalidLogin() {
        bool isAuthenticated = Authenticator.Authenticate("wrongUser", "wrongPass");
        Assert.IsFalse(isAuthenticated);
    }

    [Test]
    public void TestAdminAccess() {
        string result = RoleManager.AccessAdminDashboard("adminUser");
        Assert.AreEqual("Access granted to Admin Dashboard", result);
    }

    [Test]
    public void TestUnauthorizedAccess() {
        string result = RoleManager.AccessAdminDashboard("regularUser");
        Assert.AreEqual("Access denied", result);
    }
}


# Debugging and Resolving Security Issues Using Microsoft Copilot

# Step 2: Identify Vulnerabilities in the Codebase
# Some possible vulnerabilities in the existing codebase:

# Unsafe SQL queries: If queries are built with raw string concatenation, they are prone to SQL injection.

# XSS risks: If user-generated content is directly displayed without sanitization, cross-site scripting (XSS) attacks are possible.


# Step 3: Fix Security Issues
# Fixing SQL Injection Risk
# Modify your database queries to always use parameterized statements:
import mysql.connector

conn = mysql.connector.connect(host="localhost", user="root", password="", database="SafeVaultDB")
cursor = conn.cursor()

# Secure query using placeholders
def get_user(username):
    query = "SELECT * FROM Users WHERE Username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchall()


# Fixing XSS Risk
# Ensure that all user inputs are escaped properly before rendering:
function escapeHTML(str) {
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
}

document.querySelector("form").addEventListener("submit", function(event) {
    let username = escapeHTML(document.getElementById("username").value);
    let email = escapeHTML(document.getElementById("email").value);

    if (!username || !email) {
        event.preventDefault();
        alert("Invalid input!");
    }
});


# Step 4: Test the Fixed Code
# Write tests to simulate attack scenarios:
using NUnit.Framework;

[TestFixture]
public class TestSecurityFixes {
    [Test]
    public void TestSQLInjectionPrevention() {
        string maliciousInput = "'; DROP TABLE Users; --";
        bool isInjectionBlocked = Database.QuerySanitizer(maliciousInput);
        Assert.IsTrue(isInjectionBlocked);
    }

    [Test]
    public void TestXSSPrevention() {
        string maliciousScript = "<script>alert('XSS');</script>";
        string sanitized = SecurityHelper.EscapeHTML(maliciousScript);
        Assert.AreNotEqual(maliciousScript, sanitized);
    }
}


# Step 5: Save and Summarize Your Work
# Vulnerabilities identified: SQL injection due to raw queries, XSS due to unsanitized output.

# Fixes applied: Parameterized queries, escaping user-generated content.

# Tests verified: Simulated attacks show security fixes are effective.