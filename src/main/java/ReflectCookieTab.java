import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * UI Tab for Reflect Cookie Detector extension.
 * Displays tracked cookies, found vulnerabilities, and ignore list management.
 */
public class ReflectCookieTab implements CookieDatabase.DatabaseListener {
    private final MontoyaApi api;
    private final CookieDatabase database;
    
    private JPanel mainPanel;
    private DefaultTableModel cookieTableModel;
    private DefaultTableModel vulnerabilityTableModel;
    private JTable cookieTable;
    private JTable vulnerabilityTable;
    private JLabel statsLabel;
    
    private static final String[] COOKIE_COLUMNS = {"Name", "Domain", "Path", "HttpOnly", "Secure", "SameSite", "Ignored"};
    private static final String[] VULN_COLUMNS = {"Time", "Cookie Name", "Severity", "URL", "Reason"};

    public ReflectCookieTab(MontoyaApi api, CookieDatabase database) {
        this.api = api;
        this.database = database;
        this.database.addListener(this);
        initializeUI();
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Stats panel at top
        JPanel statsPanel = createStatsPanel();
        mainPanel.add(statsPanel, BorderLayout.NORTH);
        
        // Main split pane with cookies and vulnerabilities
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        
        // Cookies panel (top)
        JPanel cookiesPanel = createCookiesPanel();
        splitPane.setTopComponent(cookiesPanel);
        
        // Vulnerabilities panel (bottom)
        JPanel vulnerabilitiesPanel = createVulnerabilitiesPanel();
        splitPane.setBottomComponent(vulnerabilitiesPanel);
        
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Button panel at bottom
        JPanel buttonPanel = createButtonPanel();
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Initial data load
        refreshData();
    }
    
    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(new TitledBorder("Statistics"));
        
        statsLabel = new JLabel("Loading...");
        statsLabel.setFont(statsLabel.getFont().deriveFont(Font.BOLD));
        panel.add(statsLabel);
        
        return panel;
    }
    
    private JPanel createCookiesPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new TitledBorder("Tracked Cookies"));
        
        // Create table model (non-editable except for Ignored column)
        cookieTableModel = new DefaultTableModel(COOKIE_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 6; // Only "Ignored" column is editable
            }
            
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 3 || column == 4 || column == 6) { // HttpOnly, Secure, Ignored
                    return Boolean.class;
                }
                return String.class;
            }
        };
        
        cookieTable = new JTable(cookieTableModel);
        cookieTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        cookieTable.setAutoCreateRowSorter(true);
        cookieTable.getColumnModel().getColumn(6).setPreferredWidth(60);
        
        // Add listener for checkbox changes
        cookieTableModel.addTableModelListener(e -> {
            if (e.getColumn() == 6) { // Ignored column
                int row = e.getFirstRow();
                String name = (String) cookieTableModel.getValueAt(row, 0);
                String domain = (String) cookieTableModel.getValueAt(row, 1);
                Boolean ignored = (Boolean) cookieTableModel.getValueAt(row, 6);
                database.setIgnored(name, domain, ignored != null && ignored);
            }
        });
        
        JScrollPane scrollPane = new JScrollPane(cookieTable);
        scrollPane.setPreferredSize(new Dimension(800, 200));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Description label
        JLabel descLabel = new JLabel("<html><i>Check 'Ignored' to skip reflection detection for a cookie</i></html>");
        descLabel.setBorder(new EmptyBorder(5, 5, 0, 0));
        panel.add(descLabel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createVulnerabilitiesPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new TitledBorder("Detected Vulnerabilities (Reflected Cookies)"));
        
        // Create table model (read-only)
        vulnerabilityTableModel = new DefaultTableModel(VULN_COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        vulnerabilityTable = new JTable(vulnerabilityTableModel);
        vulnerabilityTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        vulnerabilityTable.setAutoCreateRowSorter(true);
        vulnerabilityTable.getColumnModel().getColumn(0).setPreferredWidth(120);
        vulnerabilityTable.getColumnModel().getColumn(3).setPreferredWidth(300);
        
        JScrollPane scrollPane = new JScrollPane(vulnerabilityTable);
        scrollPane.setPreferredSize(new Dimension(800, 200));
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> refreshData());
        panel.add(refreshButton);
        
        JButton clearButton = new JButton("Clear All Data");
        clearButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(
                mainPanel,
                "Are you sure you want to clear all tracked cookies and vulnerabilities?",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );
            if (result == JOptionPane.YES_OPTION) {
                database.clearAllData();
            }
        });
        panel.add(clearButton);
        
        JButton ignoreSelectedButton = new JButton("Ignore Selected Cookie");
        ignoreSelectedButton.addActionListener(e -> {
            int selectedRow = cookieTable.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = cookieTable.convertRowIndexToModel(selectedRow);
                String name = (String) cookieTableModel.getValueAt(modelRow, 0);
                String domain = (String) cookieTableModel.getValueAt(modelRow, 1);
                database.setIgnored(name, domain, true);
            } else {
                JOptionPane.showMessageDialog(mainPanel, "Please select a cookie first.", 
                    "No Selection", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        panel.add(ignoreSelectedButton);
        
        JButton unignoreAllButton = new JButton("Unignore All");
        unignoreAllButton.addActionListener(e -> {
            for (String key : database.getIgnoredCookies()) {
                String[] parts = key.split(":", 2);
                if (parts.length == 2) {
                    database.setIgnored(parts[0], parts[1], false);
                }
            }
        });
        panel.add(unignoreAllButton);
        
        return panel;
    }
    
    private void refreshData() {
        SwingUtilities.invokeLater(() -> {
            // Clear existing data
            cookieTableModel.setRowCount(0);
            vulnerabilityTableModel.setRowCount(0);
            
            // Load cookies
            List<CookieInfo> cookies = database.getAllCookies();
            for (CookieInfo cookie : cookies) {
                boolean ignored = database.isIgnored(cookie.getName(), cookie.getDomain());
                cookieTableModel.addRow(new Object[]{
                    cookie.getName(),
                    cookie.getDomain(),
                    cookie.getPath(),
                    cookie.isHttpOnly(),
                    cookie.isSecure(),
                    cookie.getSameSite() != null ? cookie.getSameSite() : "-",
                    ignored
                });
            }
            
            // Load vulnerabilities
            List<VulnerabilityInfo> vulnerabilities = database.getAllVulnerabilities();
            SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
            for (VulnerabilityInfo vuln : vulnerabilities) {
                vulnerabilityTableModel.addRow(new Object[]{
                    dateFormat.format(new Date(vuln.getTimestamp())),
                    vuln.getCookieName(),
                    vuln.getSeverity().toString(),
                    vuln.getUrl(),
                    vuln.getReason()
                });
            }
            
            // Update statistics
            int totalCookies = cookies.size();
            int ignoredCount = database.getIgnoredCookies().size();
            int vulnCount = vulnerabilities.size();
            long highSeverity = vulnerabilities.stream()
                .filter(v -> v.getSeverity() == burp.api.montoya.scanner.audit.issues.AuditIssueSeverity.HIGH)
                .count();
            
            statsLabel.setText(String.format(
                "Cookies: %d | Ignored: %d | Vulnerabilities: %d (High: %d)",
                totalCookies, ignoredCount, vulnCount, highSeverity
            ));
        });
    }
    
    @Override
    public void onDataChanged() {
        refreshData();
    }
    
    public Component getUiComponent() {
        return mainPanel;
    }
    
    public String getTabCaption() {
        return "Reflect Cookie";
    }
}
