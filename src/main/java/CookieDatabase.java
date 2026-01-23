import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class CookieDatabase {
    private static final String ENTRY_DELIMITER = "||";
    private static final String ENTRY_DELIMITER_REGEX = "\\|\\|";
    private static final String FIELD_DELIMITER = "|";
    private static final String KEY_DELIMITER = ":";

    private final MontoyaApi api;
    private final PersistedObject persistedData;
    private final Map<String, CookieInfo> cookieMap;
    private final Set<String> ignoredCookies;
    private final List<VulnerabilityInfo> vulnerabilities;
    private final List<DatabaseListener> listeners;

    public interface DatabaseListener {
        void onDataChanged();
    }

    public CookieDatabase(MontoyaApi api) {
        this.api = api;
        this.persistedData = api.persistence().extensionData();
        this.cookieMap = new HashMap<>();
        this.ignoredCookies = new HashSet<>();
        this.vulnerabilities = new CopyOnWriteArrayList<>();
        this.listeners = new CopyOnWriteArrayList<>();
        loadCookies();
        loadIgnoredCookies();
        loadVulnerabilities();
        api.logging().logToOutput("Cookie database initialized using Montoya Persistence API");
    }

    /**
     * Generates a unique key for a cookie based on name and domain.
     */
    public static String generateCookieKey(String name, String domain) {
        return name + KEY_DELIMITER + domain;
    }

    /**
     * Generates a unique key for a cookie including path.
     */
    private static String generateFullCookieKey(String name, String domain, String path) {
        return name + KEY_DELIMITER + domain + KEY_DELIMITER + path;
    }

    public void addListener(DatabaseListener listener) {
        listeners.add(listener);
    }

    private void notifyListeners() {
        for (DatabaseListener listener : listeners) {
            listener.onDataChanged();
        }
    }

    private void loadCookies() {
        // Load existing cookies from persisted storage
        String data = persistedData.getString("cookies");
        if (data != null && !data.isEmpty()) {
            // Parse the stored cookie data
            String[] entries = data.split(ENTRY_DELIMITER_REGEX);
            for (String entry : entries) {
                if (entry.isEmpty()) continue;
                try {
                    String[] parts = entry.split("\\|");
                    if (parts.length >= 6) {
                        String key = generateFullCookieKey(parts[0], parts[1], parts[2]);
                        CookieInfo cookie = new CookieInfo(
                            parts[0], // name
                            parts[1], // domain
                            parts[2], // path
                            Boolean.parseBoolean(parts[3]), // httpOnly
                            Boolean.parseBoolean(parts[4]), // secure
                            parts.length > 5 ? parts[5] : null // sameSite
                        );
                        cookieMap.put(key, cookie);
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error parsing cookie entry: " + e.getMessage());
                }
            }
            api.logging().logToOutput("Loaded " + cookieMap.size() + " cookies from persisted storage");
        }
    }

    private void loadIgnoredCookies() {
        String data = persistedData.getString("ignoredCookies");
        if (data != null && !data.isEmpty()) {
            String[] entries = data.split(ENTRY_DELIMITER_REGEX);
            for (String entry : entries) {
                if (!entry.isEmpty()) {
                    ignoredCookies.add(entry);
                }
            }
            api.logging().logToOutput("Loaded " + ignoredCookies.size() + " ignored cookies from persisted storage");
        }
    }

    private void saveCookies() {
        // Serialize cookies to string format
        StringBuilder sb = new StringBuilder();
        for (CookieInfo cookie : cookieMap.values()) {
            sb.append(cookie.getName()).append(FIELD_DELIMITER)
              .append(cookie.getDomain()).append(FIELD_DELIMITER)
              .append(cookie.getPath()).append(FIELD_DELIMITER)
              .append(cookie.isHttpOnly()).append(FIELD_DELIMITER)
              .append(cookie.isSecure()).append(FIELD_DELIMITER)
              .append(cookie.getSameSite() != null ? cookie.getSameSite() : "").append(ENTRY_DELIMITER);
        }
        persistedData.setString("cookies", sb.toString());
    }

    private void saveIgnoredCookies() {
        StringBuilder sb = new StringBuilder();
        for (String ignored : ignoredCookies) {
            sb.append(ignored).append(ENTRY_DELIMITER);
        }
        persistedData.setString("ignoredCookies", sb.toString());
    }

    private void loadVulnerabilities() {
        String data = persistedData.getString("vulnerabilities");
        if (data != null && !data.isEmpty()) {
            String[] entries = data.split(ENTRY_DELIMITER_REGEX);
            for (String entry : entries) {
                if (entry.isEmpty()) continue;
                try {
                    String[] parts = entry.split(FIELD_DELIMITER);
                    if (parts.length >= 5) {
                        VulnerabilityInfo vuln = new VulnerabilityInfo(
                            parts[0], // cookieName
                            parts[1], // cookieValue
                            parts[2], // url
                            AuditIssueSeverity.valueOf(parts[3]), // severity
                            parts[4]  // reason
                        );
                        vulnerabilities.add(vuln);
                    }
                } catch (Exception e) {
                    api.logging().logToError("Error parsing vulnerability entry: " + e.getMessage());
                }
            }
            api.logging().logToOutput("Loaded " + vulnerabilities.size() + " vulnerabilities from persisted storage");
        }
    }

    private void saveVulnerabilities() {
        StringBuilder sb = new StringBuilder();
        for (VulnerabilityInfo vuln : vulnerabilities) {
            sb.append(vuln.getCookieName()).append(FIELD_DELIMITER)
              .append(vuln.getCookieValue()).append(FIELD_DELIMITER)
              .append(vuln.getUrl()).append(FIELD_DELIMITER)
              .append(vuln.getSeverity()).append(FIELD_DELIMITER)
              .append(vuln.getReason()).append(ENTRY_DELIMITER);
        }
        persistedData.setString("vulnerabilities", sb.toString());
    }

    public void storeCookie(CookieInfo cookie) {
        String key = generateFullCookieKey(cookie.getName(), cookie.getDomain(), cookie.getPath());
        if (!cookieMap.containsKey(key)) {
            cookieMap.put(key, cookie);
            saveCookies();
            notifyListeners();
        }
    }

    public void addVulnerability(VulnerabilityInfo vulnerability) {
        vulnerabilities.add(vulnerability);
        saveVulnerabilities();
        notifyListeners();
    }

    public List<CookieInfo> getAllCookies() {
        return new ArrayList<>(cookieMap.values());
    }

    public List<VulnerabilityInfo> getAllVulnerabilities() {
        return new ArrayList<>(vulnerabilities);
    }

    public boolean isIgnored(String cookieName, String domain) {
        String key = generateCookieKey(cookieName, domain);
        return ignoredCookies.contains(key);
    }

    public void setIgnored(String cookieName, String domain, boolean ignored) {
        String key = generateCookieKey(cookieName, domain);
        if (ignored) {
            ignoredCookies.add(key);
        } else {
            ignoredCookies.remove(key);
        }
        saveIgnoredCookies();
        notifyListeners();
    }

    public Set<String> getIgnoredCookies() {
        return new HashSet<>(ignoredCookies);
    }

    public void clearAllData() {
        cookieMap.clear();
        vulnerabilities.clear();
        ignoredCookies.clear();
        saveCookies();
        saveIgnoredCookies();
        saveVulnerabilities();
        notifyListeners();
        api.logging().logToOutput("All cookie data cleared");
    }

    public boolean cookieExists(String name, String domain) {
        // Check if any cookie with this name and domain exists (regardless of path)
        String prefix = name + KEY_DELIMITER + domain + KEY_DELIMITER;
        for (String key : cookieMap.keySet()) {
            if (key.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
