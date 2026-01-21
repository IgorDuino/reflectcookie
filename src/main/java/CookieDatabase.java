import burp.api.montoya.MontoyaApi;

import java.sql.*;

public class CookieDatabase {
    private final Connection connection;
    private final MontoyaApi api;

    public CookieDatabase(MontoyaApi api, String projectName) throws SQLException {
        this.api = api;
        String dbPath = System.getProperty("user.home") + "/.burp/reflectcookie_" + sanitizeFileName(projectName) + ".db";
        connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        initializeDatabase();
        api.logging().logToOutput("Cookie database initialized at: " + dbPath);
    }

    private String sanitizeFileName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_-]", "_");
    }

    private void initializeDatabase() throws SQLException {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS cookies (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT NOT NULL," +
                "domain TEXT NOT NULL," +
                "path TEXT," +
                "httponly INTEGER NOT NULL," +
                "secure INTEGER NOT NULL," +
                "samesite TEXT," +
                "first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP," +
                "UNIQUE(name, domain, path)" +
                ")";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(createTableSQL);
        }
    }

    public void storeCookie(CookieInfo cookie) {
        String insertSQL = "INSERT OR IGNORE INTO cookies (name, domain, path, httponly, secure, samesite) VALUES (?, ?, ?, ?, ?, ?)";
        
        try (PreparedStatement pstmt = connection.prepareStatement(insertSQL)) {
            pstmt.setString(1, cookie.getName());
            pstmt.setString(2, cookie.getDomain());
            pstmt.setString(3, cookie.getPath());
            pstmt.setInt(4, cookie.isHttpOnly() ? 1 : 0);
            pstmt.setInt(5, cookie.isSecure() ? 1 : 0);
            pstmt.setString(6, cookie.getSameSite());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            api.logging().logToError("Error storing cookie: " + e.getMessage());
        }
    }

    public boolean cookieExists(String name, String domain) {
        String selectSQL = "SELECT COUNT(*) FROM cookies WHERE name = ? AND domain = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, name);
            pstmt.setString(2, domain);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1) > 0;
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error checking cookie existence: " + e.getMessage());
        }
        return false;
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            api.logging().logToError("Error closing database: " + e.getMessage());
        }
    }
}
