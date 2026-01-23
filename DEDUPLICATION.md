# Issue Deduplication Mechanism

## Overview

This document describes the deduplication mechanism implemented to prevent duplicate issues from being created when the same reflected cookie is detected multiple times.

## Problem

Previously, the extension would create a new issue every time a reflected cookie was detected in an HTTP response. This meant that:
- Repeated requests to the same URL would generate duplicate issues
- Burp's site map would become cluttered with redundant entries
- Users would see multiple identical alerts for the same vulnerability

## Solution

The deduplication mechanism tracks all reported issues using a unique identifier and prevents duplicate issue creation.

### Implementation Details

1. **Issue Tracking**: A `Set<String>` called `reportedIssues` maintains a list of all issues that have been created.

2. **Unique Identifier**: Each issue is identified by a unique key combining:
   - Cookie name
   - Request URL
   
   Format: `cookieName:URL`

3. **Persistence**: The reported issues are persisted using the Montoya Persistence API:
   - Issues are saved to the Burp project file (or memory if no project is open)
   - On extension reload, previously reported issues are restored
   - This prevents duplicate issues across Burp sessions

4. **Deduplication Check**: Before creating a new issue, the system:
   - Generates the unique key for the issue
   - Checks if it exists in `reportedIssues`
   - If it exists, skips creation (early return)
   - If it doesn't exist, creates the issue and adds the key to the set

### Code Flow

```
1. Cookie reflected in response detected
2. Generate issue key: cookieName:URL
3. Check if key exists in reportedIssues
   ├─ Yes → Skip creation (return early)
   └─ No  → Create issue
           └─ Add key to reportedIssues
           └─ Save to persistence
```

## Benefits

- **No Duplicate Issues**: Same cookie/URL combination only generates one issue
- **Cleaner Site Map**: Burp's issue list remains clean and manageable
- **Better User Experience**: Users see unique issues without redundancy
- **Persistent Across Sessions**: Deduplication persists when using Burp project files

## Example

Consider this scenario:

1. User makes request to `https://example.com/api/login`
2. Response sets cookie `sessionid=abc123` which is reflected in response body
3. Extension creates issue with key `sessionid:https://example.com/api/login`
4. User makes the same request again (or Burp scanner repeats it)
5. Extension detects the same reflected cookie
6. **Deduplication check prevents duplicate issue creation**
7. No new issue is added to the site map

## Technical Notes

- Issue keys are case-sensitive
- The deduplication is based on cookie name and URL only, not cookie value
- If the same cookie name is reflected on different URLs, separate issues will be created
- Persistence uses Burp's native Montoya API, no external dependencies required
