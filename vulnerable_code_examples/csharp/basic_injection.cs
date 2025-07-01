using System;
using System.Data;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Text.RegularExpressions;

/**
 * Basic SQL Injection Vulnerable Code Examples
 * C# examples demonstrating common SQL injection vulnerabilities
 * 
 * WARNING: This code is intentionally vulnerable and should ONLY be used for:
 * - Educational purposes
 * - Security research
 * - Testing security tools
 * - Academic studies
 * 
 * NEVER use this code in production environments!
 */

namespace VulnerableCodeExamples
{
    public class BasicInjection
    {
        private static readonly string ConnectionString = "Server=localhost;Database=testdb;User Id=root;Password=password;";
        
        // ============================================================================
        // BASIC STRING CONCATENATION VULNERABILITIES
        // ============================================================================
        
        public bool VulnerableLogin1(string username, string password)
        {
            // VULNERABLE: Direct string concatenation
            string query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        return reader.HasRows;
                    }
                }
            }
        }
        
        public bool VulnerableLogin2(string username, string password)
        {
            // VULNERABLE: String interpolation
            string query = $"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'";
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        return reader.HasRows;
                    }
                }
            }
        }
        
        public bool VulnerableLogin3(string username, string password)
        {
            // VULNERABLE: String.Format
            string query = string.Format("SELECT * FROM users WHERE username = '{0}' AND password = '{1}'", username, password);
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        return reader.HasRows;
                    }
                }
            }
        }
        
        // ============================================================================
        // SEARCH FUNCTIONALITY VULNERABILITIES
        // ============================================================================
        
        public List<string> VulnerableSearch1(string searchTerm)
        {
            // VULNERABLE: String concatenation in LIKE
            string query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
            List<string> products = new List<string>();
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            products.Add(reader["name"].ToString());
                        }
                    }
                }
            }
            
            return products;
        }
        
        public List<string> VulnerableSearch2(string searchTerm)
        {
            // VULNERABLE: String interpolation in LIKE
            string query = $"SELECT * FROM products WHERE name LIKE '%{searchTerm}%'";
            List<string> products = new List<string>();
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            products.Add(reader["name"].ToString());
                        }
                    }
                }
            }
            
            return products;
        }
        
        // ============================================================================
        // DATA MANIPULATION VULNERABILITIES
        // ============================================================================
        
        public bool VulnerableInsert(string name, string email)
        {
            // VULNERABLE: String concatenation in INSERT
            string query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')";
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return rowsAffected > 0;
                }
            }
        }
        
        public bool VulnerableUpdate(int userId, string newName)
        {
            // VULNERABLE: String concatenation in UPDATE
            string query = "UPDATE users SET name = '" + newName + "' WHERE id = " + userId;
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return rowsAffected > 0;
                }
            }
        }
        
        public bool VulnerableDelete(int userId)
        {
            // VULNERABLE: String concatenation in DELETE
            string query = "DELETE FROM users WHERE id = " + userId;
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    int rowsAffected = command.ExecuteNonQuery();
                    return rowsAffected > 0;
                }
            }
        }
        
        // ============================================================================
        // INPUT VALIDATION BYPASSES
        // ============================================================================
        
        public string BypassSimpleValidation(string userInput)
        {
            // VULNERABLE: Inadequate validation
            if (userInput.Contains("'") || userInput.Contains(";"))
            {
                return "Invalid input";
            }
            
            // Still vulnerable to other injection techniques
            string query = "SELECT * FROM users WHERE id = " + userInput;
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return reader["name"].ToString();
                        }
                    }
                }
            }
            
            return null;
        }
        
        public string BypassRegexValidation(string userInput)
        {
            // VULNERABLE: Regex can be bypassed
            if (!Regex.IsMatch(userInput, @"^[0-9]+$"))
            {
                return "Invalid input";
            }
            
            // Still vulnerable to numeric injection
            string query = "SELECT * FROM users WHERE id = " + userInput + " OR 1=1";
            
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                connection.Open();
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return reader["name"].ToString();
                        }
                    }
                }
            }
            
            return null;
        }
        
        // ============================================================================
        // SUPPORTING CLASSES
        // ============================================================================
        
        public class LoginRequest
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }
        
        public class User
        {
            public int Id { get; set; }
            public string Name { get; set; }
            public string Email { get; set; }
        }
    }
} 