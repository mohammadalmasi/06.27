import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Basic SQL Injection Vulnerable Code Examples
 * Java examples demonstrating common SQL injection vulnerabilities
 * 
 * WARNING: This code is intentionally vulnerable and should ONLY be used for:
 * - Educational purposes
 * - Security research
 * - Testing security tools
 * - Academic studies
 * 
 * NEVER use this code in production environments!
 */

public class BasicInjection {
    
    // Database connection parameters
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String USER = "root";
    private static final String PASS = "password";
    
    // ============================================================================
    // BASIC STRING CONCATENATION VULNERABILITIES
    // ============================================================================
    
    public boolean vulnerableLogin1(String username, String password) {
        // VULNERABLE: Direct string concatenation
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            return rs.next(); // Returns true if user exists
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean vulnerableLogin2(String username, String password) {
        // VULNERABLE: String.format
        String query = String.format("SELECT * FROM users WHERE username = '%s' AND password = '%s'", username, password);
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean vulnerableLogin3(String username, String password) {
        // VULNERABLE: StringBuilder
        StringBuilder query = new StringBuilder();
        query.append("SELECT * FROM users WHERE username = '").append(username).append("' AND password = '").append(password).append("'");
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query.toString())) {
            
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // ============================================================================
    // SEARCH FUNCTIONALITY VULNERABILITIES
    // ============================================================================
    
    public List<String> vulnerableSearch1(String searchTerm) {
        // VULNERABLE: String concatenation in LIKE
        String query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
        List<String> products = new ArrayList<>();
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                products.add(rs.getString("name"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return products;
    }
    
    public List<String> vulnerableSearch2(String searchTerm) {
        // VULNERABLE: String.format in LIKE
        String query = String.format("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchTerm);
        List<String> products = new ArrayList<>();
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                products.add(rs.getString("name"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return products;
    }
    
    // ============================================================================
    // DATA MANIPULATION VULNERABILITIES
    // ============================================================================
    
    public boolean vulnerableInsert(String name, String email) {
        // VULNERABLE: String concatenation in INSERT
        String query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            int rowsAffected = stmt.executeUpdate(query);
            return rowsAffected > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean vulnerableUpdate(int userId, String newName) {
        // VULNERABLE: String concatenation in UPDATE
        String query = "UPDATE users SET name = '" + newName + "' WHERE id = " + userId;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            int rowsAffected = stmt.executeUpdate(query);
            return rowsAffected > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean vulnerableDelete(int userId) {
        // VULNERABLE: String concatenation in DELETE
        String query = "DELETE FROM users WHERE id = " + userId;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            int rowsAffected = stmt.executeUpdate(query);
            return rowsAffected > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // ============================================================================
    // PREPARED STATEMENT MISUSE VULNERABILITIES
    // ============================================================================
    
    public boolean vulnerablePreparedStatement1(String username, String password) {
        // VULNERABLE: Prepared statement with string concatenation
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement pstmt = conn.prepareStatement(query);
             ResultSet rs = pstmt.executeQuery()) {
            
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public boolean vulnerablePreparedStatement2(String userId) {
        // VULNERABLE: Prepared statement with string concatenation
        String query = "SELECT * FROM users WHERE id = " + userId;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement pstmt = conn.prepareStatement(query);
             ResultSet rs = pstmt.executeQuery()) {
            
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // ============================================================================
    // JDBC VULNERABILITIES
    // ============================================================================
    
    public String vulnerableJdbcQuery(String userId) {
        // VULNERABLE: JDBC with string concatenation
        String query = "SELECT name FROM users WHERE id = " + userId;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return rs.getString("name");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
    public List<String> vulnerableJdbcBatch(String[] names) {
        // VULNERABLE: Batch operations with string concatenation
        List<String> results = new ArrayList<>();
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement()) {
            
            for (String name : names) {
                String query = "INSERT INTO users (name) VALUES ('" + name + "')";
                stmt.addBatch(query);
            }
            
            int[] results_array = stmt.executeBatch();
            for (int result : results_array) {
                results.add("Rows affected: " + result);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return results;
    }
    
    // ============================================================================
    // INPUT VALIDATION BYPASSES
    // ============================================================================
    
    public String bypassSimpleValidation(String userInput) {
        // VULNERABLE: Inadequate validation
        if (userInput.contains("'") || userInput.contains(";")) {
            return "Invalid input";
        }
        
        // Still vulnerable to other injection techniques
        String query = "SELECT * FROM users WHERE id = " + userInput;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return rs.getString("name");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
    public String bypassRegexValidation(String userInput) {
        // VULNERABLE: Regex can be bypassed
        if (!userInput.matches("^[0-9]+$")) {
            return "Invalid input";
        }
        
        // Still vulnerable to numeric injection
        String query = "SELECT * FROM users WHERE id = " + userInput + " OR 1=1";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return rs.getString("name");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
    // ============================================================================
    // WEB APPLICATION EXAMPLES (Servlet-like)
    // ============================================================================
    
    public String handleGetRequest(String userId) {
        // VULNERABLE: GET parameter injection
        String query = "SELECT * FROM users WHERE id = " + userId;
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            if (rs.next()) {
                return rs.getString("name");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        return null;
    }
    
    public boolean handlePostRequest(String username, String password) {
        // VULNERABLE: POST parameter injection
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // ============================================================================
    // MAIN METHOD FOR TESTING
    // ============================================================================
    
    public static void main(String[] args) {
        BasicInjection injection = new BasicInjection();
        
        // Test vulnerable login
        boolean result = injection.vulnerableLogin1("admin' OR '1'='1", "password");
        System.out.println("Login result: " + result);
        
        // Test vulnerable search
        List<String> products = injection.vulnerableSearch1("test' UNION SELECT 1,2,3,4 --");
        System.out.println("Search results: " + products);
        
        // Test vulnerable insert
        boolean insertResult = injection.vulnerableInsert("test', 'test@test.com'); DROP TABLE users; --", "test@test.com");
        System.out.println("Insert result: " + insertResult);
    }
} 