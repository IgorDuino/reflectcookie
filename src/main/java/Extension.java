import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import java.sql.SQLException;

public class Extension implements BurpExtension {
    private CookieDatabase database;
    
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Reflect Cookie Detector");

        try {
            // Initialize the database with a default project name
            // In a real scenario, you might want to get the project name from Burp settings
            database = new CookieDatabase(montoyaApi, "default");
            
            // Register the HTTP handler to monitor responses
            ReflectedCookieHandler handler = new ReflectedCookieHandler(montoyaApi, database);
            montoyaApi.http().registerHttpHandler(handler);
            
            montoyaApi.logging().logToOutput("Reflect Cookie Detector extension loaded successfully!");
            montoyaApi.logging().logToOutput("The extension will monitor all in-scope responses for reflected cookies.");
            montoyaApi.logging().logToOutput("Cookies will be stored in SQLite database for tracking.");
            
        } catch (SQLException e) {
            montoyaApi.logging().logToError("Failed to initialize cookie database: " + e.getMessage());
        }
    }
}
