import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import java.util.HashMap;
import java.util.Map;

public class CookieDatabase {
    private final MontoyaApi api;
    private final PersistedObject persistedData;
    private final Map<String, CookieInfo> cookieMap;

    public CookieDatabase(MontoyaApi api) {
        this.api = api;
        this.persistedData = api.persistence().extensionData();
        this.cookieMap = new HashMap<>();
        loadCookies();
        api.logging().logToOutput("Cookie database initialized using Montoya Persistence API");
    }

    private void loadCookies() {
        // Load existing cookies from persisted storage
        String data = persistedData.getString("cookies");
        if (data != null && !data.isEmpty()) {
            // Parse the stored cookie data
            String[] entries = data.split("\\|\\|");
            for (String entry : entries) {
                if (entry.isEmpty()) continue;
                try {
                    String[] parts = entry.split("\\|");
                    if (parts.length >= 6) {
                        String key = parts[0] + ":" + parts[1] + ":" + parts[2]; // name:domain:path
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

    private void saveCookies() {
        // Serialize cookies to string format
        StringBuilder sb = new StringBuilder();
        for (CookieInfo cookie : cookieMap.values()) {
            sb.append(cookie.getName()).append("|")
              .append(cookie.getDomain()).append("|")
              .append(cookie.getPath()).append("|")
              .append(cookie.isHttpOnly()).append("|")
              .append(cookie.isSecure()).append("|")
              .append(cookie.getSameSite() != null ? cookie.getSameSite() : "").append("||");
        }
        persistedData.setString("cookies", sb.toString());
    }

    public void storeCookie(CookieInfo cookie) {
        String key = cookie.getName() + ":" + cookie.getDomain() + ":" + cookie.getPath();
        if (!cookieMap.containsKey(key)) {
            cookieMap.put(key, cookie);
            saveCookies();
        }
    }

    public boolean cookieExists(String name, String domain) {
        // Check if any cookie with this name and domain exists (regardless of path)
        for (String key : cookieMap.keySet()) {
            if (key.startsWith(name + ":" + domain + ":")) {
                return true;
            }
        }
        return false;
    }
}
