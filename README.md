# Reflect Cookie Detector

A Burp Suite extension that detects reflected cookies in server responses to help identify potential XSS vulnerabilities.

## Overview

This extension monitors HTTP responses for cookies that are reflected in the response body. It stores cookie information using Burp's native Persistence API and creates audit issues based on the severity of the finding.

## Features

- **Automatic Cookie Detection**: Monitors all in-scope HTTP responses for cookies
- **Native Burp Persistence**: Stores cookie information (name, domain, path, HttpOnly, Secure, SameSite) using Montoya API's Persistence API
- **Reflected Cookie Detection**: Identifies when cookie values appear in response bodies
- **Risk-Based Issue Creation**: Creates audit issues with severity levels based on:
  - **INFORMATION**: Cookie missing HttpOnly flag
  - **LOW**: Cookie has HttpOnly flag but name is not sensitive
  - **HIGH**: Cookie has HttpOnly flag AND name contains sensitive keywords (session, secret, token, auth, jwt, sid, sso, bearer, key)

## Installation

### Prerequisites

- Burp Suite Professional or Community Edition
- Java 17 or higher

### Building the Extension

1. Clone this repository
2. Build the JAR file:
   ```bash
   ./gradlew jar
   ```
3. The JAR file will be created in `build/libs/extension-template-project.jar`

### Loading into Burp Suite

1. In Burp Suite, go to **Extensions > Installed**
2. Click **Add**
3. Under **Extension details**, click **Select file**
4. Select the JAR file from `build/libs/`
5. Click **Next** to load the extension

## Usage

1. Ensure your target is added to Burp's scope
2. Browse the target application or run a scan
3. The extension will automatically:
   - Monitor all in-scope responses
   - Store cookies using Burp's persistence mechanism
   - Create issues when reflected cookies are detected
4. View detected issues in the **Target > Issues** tab

## Data Storage

The extension uses Burp's native **Persistence API** (`montoyaApi.persistence().extensionData()`):
- Data is stored in the Burp project file when a project is open
- Data is stored in memory when Burp runs without a project file
- No external database files or dependencies required
- Cookie data persists across Burp sessions when using project files

## Issue Details

When a reflected cookie is detected, the extension creates an issue with:
- **Issue Name**: "Reflected Cookie in Response"
- **Severity**: Based on HttpOnly flag and cookie name
- **Details**: Cookie properties including domain, path, flags, and SameSite policy
- **Evidence**: The HTTP request and response containing the reflected cookie

## Development

### Project Structure

- `Extension.java` - Main extension class
- `ReflectedCookieHandler.java` - HTTP handler for detecting reflected cookies
- `CookieDatabase.java` - Persistence layer using Montoya API
- `CookieInfo.java` - Cookie information model

### Building and Testing

```bash
# Build the project
./gradlew build

# Run tests
./gradlew test

# Create JAR
./gradlew jar
```

## Architecture Benefits

This extension uses Montoya API's native Persistence API instead of external databases:
- **No external dependencies**: Reduced JAR size from 14MB to 8KB
- **Project integration**: Data automatically saved with Burp project files
- **Simplicity**: No database setup or file management required
- **Resource efficiency**: Burp handles all storage operations

## Related Resources

* [Montoya API JavaDoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
* [Burp Extension Documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating)
* [Example Extensions](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)

## License

This project uses the Burp Suite Montoya API and follows PortSwigger's extension guidelines.

