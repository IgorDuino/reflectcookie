import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("Reflect Cookie Detector");

        // Initialize the database using Montoya Persistence API
        CookieDatabase database = new CookieDatabase(montoyaApi);
        
        // Register the HTTP handler to monitor responses
        ReflectedCookieHandler handler = new ReflectedCookieHandler(montoyaApi, database);
        montoyaApi.http().registerHttpHandler(handler);
        
        // Register the UI tab
        ReflectCookieTab tab = new ReflectCookieTab(montoyaApi, database);
        montoyaApi.userInterface().registerSuiteTab(tab.getTabCaption(), tab.getUiComponent());
        
        montoyaApi.logging().logToOutput("Reflect Cookie Detector extension loaded successfully!");
        montoyaApi.logging().logToOutput("The extension will monitor all in-scope responses for reflected cookies.");
        montoyaApi.logging().logToOutput("Cookies will be stored in Burp project data for tracking.");
        montoyaApi.logging().logToOutput("Use the 'Reflect Cookie' tab to view and manage tracked cookies.");
    }
}
