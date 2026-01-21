# Example Usage

This document demonstrates how the Reflect Cookie Detector extension works in practice.

## Scenario 1: Cookie without HttpOnly flag (INFORMATION severity)

**HTTP Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: user_id=12345; Path=/; Secure
Content-Type: text/html

<html>
<body>
  <p>Welcome! Your user ID is: 12345</p>
</body>
</html>
```

**Extension Behavior:**
1. Detects cookie `user_id` with value `12345`
2. Parses cookie attributes: HttpOnly=false, Secure=true
3. Detects that value `12345` is reflected in the response body
4. Stores cookie in Burp project data using Persistence API
5. Creates audit issue with **INFORMATION** severity (no HttpOnly flag)

**Issue Details:**
- **Title:** "Reflected Cookie in Response"
- **Severity:** INFORMATION
- **Reason:** Cookie does not have HttpOnly flag set
- **Cookie Properties:**
  - Name: user_id
  - Domain: example.com
  - Path: /
  - HttpOnly: No
  - Secure: Yes
  - SameSite: Not set

---

## Scenario 2: Sensitive cookie with HttpOnly flag (HIGH severity)

**HTTP Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: session_token=abc123xyz; Path=/; HttpOnly; Secure; SameSite=Strict
Content-Type: text/html

<html>
<body>
  <input type="hidden" name="csrf" value="abc123xyz">
</body>
</html>
```

**Extension Behavior:**
1. Detects cookie `session_token` with value `abc123xyz`
2. Parses cookie attributes: HttpOnly=true, Secure=true, SameSite=Strict
3. Detects that value `abc123xyz` is reflected in the response body
4. Stores cookie in Burp project data
5. Creates audit issue with **HIGH** severity (HttpOnly present + sensitive keyword "session")

**Issue Details:**
- **Title:** "Reflected Cookie in Response"
- **Severity:** HIGH
- **Reason:** Cookie has HttpOnly flag but name contains sensitive keyword
- **Cookie Properties:**
  - Name: session_token
  - Domain: example.com
  - Path: /
  - HttpOnly: Yes
  - Secure: Yes
  - SameSite: Strict

---

## Scenario 3: Non-sensitive cookie with HttpOnly flag (LOW severity)

**HTTP Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: preferences=dark_mode; Path=/; HttpOnly
Content-Type: application/json

{"theme": "dark_mode", "status": "ok"}
```

**Extension Behavior:**
1. Detects cookie `preferences` with value `dark_mode`
2. Parses cookie attributes: HttpOnly=true, Secure=false
3. Detects that value `dark_mode` is reflected in the response body
4. Stores cookie in Burp project data
5. Creates audit issue with **LOW** severity (HttpOnly present + non-sensitive name)

**Issue Details:**
- **Title:** "Reflected Cookie in Response"
- **Severity:** LOW
- **Reason:** Cookie has HttpOnly flag and name is not sensitive
- **Cookie Properties:**
  - Name: preferences
  - Domain: example.com
  - Path: /
  - HttpOnly: Yes
  - Secure: No
  - SameSite: Not set

---

## Data Persistence

The extension uses Burp's native **Persistence API** for storage:

### Storage Mechanism
```java
// Access persisted data
PersistedObject persistedData = api.persistence().extensionData();

// Store cookies as serialized string
persistedData.setString("cookies", serializedCookieData);

// Retrieve cookies
String data = persistedData.getString("cookies");
```

### Storage Location
- **With Burp Project**: Data saved in the `.burp` project file
- **Without Project**: Data stored in memory (lost on restart)

### Data Format
Cookies are stored as pipe-delimited strings:
```
name|domain|path|httponly|secure|samesite||name2|domain2|path2|httponly2|secure2|samesite2||
```

Each cookie is stored only once per unique combination of (name, domain, path).

---

## Sensitive Keywords

The extension considers a cookie name sensitive if it contains any of these keywords (case-insensitive):

- session
- secret
- token
- auth
- jwt
- sid
- sso
- bearer
- key

Examples of sensitive cookie names:
- `session_id`
- `auth_token`
- `JWT_ACCESS`
- `bearer_token`
- `api_key`
- `SESSION`
- `secret_value`
- `SSO_TOKEN`

---

## Benefits of Persistence API

1. **Project Integration**: Cookie data automatically included in Burp project files
2. **No External Files**: No separate database files to manage
3. **Memory Efficiency**: Data stored in memory when no project is open
4. **Portability**: Moving a `.burp` project file includes all extension data
5. **Simplicity**: No database schema or SQL queries needed
