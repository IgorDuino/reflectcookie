# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This is a Burp Suite Extension that detects reflected cookies in server responses using the Montoya API.

## Architecture

- **Main Entry Point**: `src/main/java/Extension.java` - implements `BurpExtension` interface
- **HTTP Handler**: `src/main/java/ReflectedCookieHandler.java` - monitors HTTP responses for reflected cookies
- **Database Manager**: `src/main/java/CookieDatabase.java` - manages SQLite storage of cookie information
- **Cookie Model**: `src/main/java/CookieInfo.java` - represents cookie properties
- **Build System**: Gradle with Kotlin DSL, Java 17 compatibility
- **Dependencies**: Montoya API 2025.10 (compile-only), SQLite JDBC 3.47.1.0 (implementation)

## Functionality

### Core Features
1. **Cookie Detection**: Monitors all in-scope HTTP responses for Set-Cookie headers
2. **Cookie Storage**: Stores cookie details (name, domain, path, HttpOnly, Secure, SameSite) in SQLite database
3. **Reflection Detection**: Checks if cookie values appear in response bodies
4. **Issue Creation**: Generates Burp audit issues with risk-based severity:
   - INFORMATION: Cookie without HttpOnly flag
   - LOW: Cookie with HttpOnly but non-sensitive name
   - HIGH: Cookie with HttpOnly AND sensitive keyword in name (session, secret, token, auth, jwt, sid, sso, bearer, key)

### Database
- Location: `~/.burp/reflectcookie_default.db`
- Schema: cookies table with fields (id, name, domain, path, httponly, secure, samesite, first_seen)
- Unique constraint on (name, domain, path)

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` and can be loaded directly into Burp Suite.

## Extension Loading in Burp

1. Build the JAR using `./gradlew jar`
2. In Burp: Extensions > Installed > Add > Select the JAR file
3. For quick reloading during development: Ctrl/⌘ + click the Loaded checkbox

## Documentation Structure

- See @docs/bapp-store-requirements.md for BApp Store submission requirements
- See @docs/montoya-api-examples.md for code patterns and extension structure  
- See @docs/development-best-practices.md for development guidelines
- See @docs/resources.md for external documentation and links

## Current State

This extension is fully functional and includes:
- Automatic detection of reflected cookies in HTTP responses
- SQLite database storage for cookie tracking
- Risk-based issue generation in Burp's site map
- Comprehensive logging of detected issues

