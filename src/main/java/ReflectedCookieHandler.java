import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ReflectedCookieHandler implements HttpHandler {
    private final MontoyaApi api;
    private final CookieDatabase database;
    
    private static final Set<String> SENSITIVE_KEYWORDS = new HashSet<>(Arrays.asList(
            "session", "secret", "token", "auth", "jwt", "sid", "sso", "bearer", "key"
    ));

    public ReflectedCookieHandler(MontoyaApi api, CookieDatabase database) {
        this.api = api;
        this.database = database;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Check if the response is in scope
        if (!api.scope().isInScope(responseReceived.initiatingRequest().url())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        HttpResponse response = responseReceived;
        List<Cookie> cookies = response.cookies();

        for (Cookie cookie : cookies) {
            String cookieName = cookie.name();
            String cookieValue = cookie.value();
            String domain = cookie.domain() != null ? cookie.domain() : responseReceived.initiatingRequest().httpService().host();
            String path = cookie.path() != null ? cookie.path() : "/";
            
            // Parse cookie attributes from Set-Cookie header
            boolean httpOnly = isHttpOnly(response, cookieName);
            boolean secure = isSecure(response, cookieName);
            String sameSite = getSameSite(response, cookieName);

            // Create cookie info
            CookieInfo cookieInfo = new CookieInfo(cookieName, domain, path, httpOnly, secure, sameSite);
            
            // Store cookie in database
            database.storeCookie(cookieInfo);

            // Check if cookie value is reflected in response body
            String responseBody = response.bodyToString();
            if (cookieValue != null && !cookieValue.isEmpty() && responseBody.contains(cookieValue)) {
                // Cookie is reflected, create an issue
                createReflectedCookieIssue(responseReceived, cookieInfo, cookieValue);
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private boolean isHttpOnly(HttpResponse response, String cookieName) {
        // Parse Set-Cookie headers to check for HttpOnly flag
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String value = header.value();
                if (value.toLowerCase().startsWith(cookieName.toLowerCase() + "=")) {
                    return value.toLowerCase().contains("httponly");
                }
            }
        }
        return false;
    }

    private boolean isSecure(HttpResponse response, String cookieName) {
        // Parse Set-Cookie headers to check for Secure flag
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String value = header.value();
                if (value.toLowerCase().startsWith(cookieName.toLowerCase() + "=")) {
                    return value.toLowerCase().contains("secure");
                }
            }
        }
        return false;
    }

    private String getSameSite(HttpResponse response, String cookieName) {
        // Parse Set-Cookie headers to extract SameSite attribute
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String value = header.value();
                if (value.toLowerCase().startsWith(cookieName.toLowerCase() + "=")) {
                    if (value.toLowerCase().contains("samesite=strict")) {
                        return "Strict";
                    } else if (value.toLowerCase().contains("samesite=lax")) {
                        return "Lax";
                    } else if (value.toLowerCase().contains("samesite=none")) {
                        return "None";
                    }
                }
            }
        }
        return null;
    }

    private void createReflectedCookieIssue(HttpResponseReceived responseReceived, CookieInfo cookie, String cookieValue) {
        // Determine severity based on httpOnly flag and cookie name
        AuditIssueSeverity severity;
        String severityReason;
        
        if (!cookie.isHttpOnly()) {
            severity = AuditIssueSeverity.INFORMATION;
            severityReason = "Cookie does not have HttpOnly flag set";
        } else if (containsSensitiveKeyword(cookie.getName())) {
            severity = AuditIssueSeverity.HIGH;
            severityReason = "Cookie has HttpOnly flag but name contains sensitive keyword";
        } else {
            severity = AuditIssueSeverity.LOW;
            severityReason = "Cookie has HttpOnly flag and name is not sensitive";
        }

        String issueDetail = String.format(
                "The cookie '%s' with value '%s' is reflected in the response body. " +
                "This could potentially lead to XSS vulnerabilities.<br><br>" +
                "<b>Cookie Properties:</b><br>" +
                "Domain: %s<br>" +
                "Path: %s<br>" +
                "HttpOnly: %s<br>" +
                "Secure: %s<br>" +
                "SameSite: %s<br><br>" +
                "<b>Severity Reason:</b> %s",
                cookie.getName(),
                cookieValue.length() > 50 ? cookieValue.substring(0, 50) + "..." : cookieValue,
                cookie.getDomain(),
                cookie.getPath(),
                cookie.isHttpOnly() ? "Yes" : "No",
                cookie.isSecure() ? "Yes" : "No",
                cookie.getSameSite() != null ? cookie.getSameSite() : "Not set",
                severityReason
        );

        // Create HttpRequestResponse from the responseReceived
        HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                responseReceived.initiatingRequest(),
                responseReceived
        );

        AuditIssue issue = AuditIssue.auditIssue(
                "Reflected Cookie in Response",
                issueDetail,
                null,  // remediation
                responseReceived.initiatingRequest().url(),
                severity,
                AuditIssueConfidence.CERTAIN,
                null,  // background
                null,  // remediationBackground
                AuditIssueSeverity.INFORMATION,  // typicalSeverity
                requestResponse
        );

        api.siteMap().add(issue);
        
        // Log the issue
        api.logging().logToOutput(String.format(
                "Reflected cookie detected: %s [Severity: %s] at %s",
                cookie.getName(),
                severity,
                responseReceived.initiatingRequest().url()
        ));
    }

    private boolean containsSensitiveKeyword(String cookieName) {
        String lowerCaseName = cookieName.toLowerCase();
        for (String keyword : SENSITIVE_KEYWORDS) {
            if (lowerCaseName.contains(keyword)) {
                return true;
            }
        }
        return false;
    }
}
