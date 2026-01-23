# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This is a Burp Suite Extension that detects reflected cookies in server responses using the Montoya API.

## Architecture

- **Main Entry Point**: `src/main/java/Extension.java` - implements `BurpExtension` interface
- **HTTP Handler**: `src/main/java/ReflectedCookieHandler.java` - monitors HTTP responses for reflected cookies
- **Persistence Manager**: `src/main/java/CookieDatabase.java` - manages cookie storage using Montoya Persistence API
- **Cookie Model**: `src/main/java/CookieInfo.java` - represents cookie properties
- **Build System**: Gradle with Kotlin DSL, Java 17 compatibility
- **Dependencies**: Montoya API 2025.10 (compile-only only, no runtime dependencies)

## Functionality

### Core Features
1. **Cookie Detection**: Monitors all in-scope HTTP responses for Set-Cookie headers
2. **Cookie Storage**: Stores cookie details (name, domain, path, HttpOnly, Secure, SameSite) using Montoya Persistence API
3. **Reflection Detection**: Checks if cookie values appear in response bodies
4. **Issue Creation**: Generates Burp audit issues with risk-based severity:
   - INFORMATION: Cookie without HttpOnly flag
   - LOW: Cookie with HttpOnly but non-sensitive name
   - HIGH: Cookie with HttpOnly AND sensitive keyword in name (session, secret, token, auth, jwt, sid, sso, bearer, key)

### Data Persistence
- Uses `montoyaApi.persistence().extensionData()` for storage
- Data stored in Burp project file when project is open
- Data stored in memory when Burp runs without project
- No external database files or dependencies required
- Cookie data persists across Burp sessions when using project files

## Key Development Commands

```bash
./gradlew build    # Build and test the extension
./gradlew jar      # Create the extension JAR file
./gradlew clean    # Clean build artifacts
```

The built JAR file will be in `build/libs/` (approximately 8KB) and can be loaded directly into Burp Suite.

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
- Native Burp Persistence API for cookie tracking
- Risk-based issue generation in Burp's site map
- Comprehensive logging of detected issues
- Minimal JAR size (8KB) with no external dependencies

