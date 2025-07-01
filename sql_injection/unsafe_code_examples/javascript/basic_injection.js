/**
 * Basic SQL Injection Vulnerable Code Examples
 * JavaScript (Node.js) examples demonstrating common SQL injection vulnerabilities
 * 
 * WARNING: This code is intentionally vulnerable and should ONLY be used for:
 * - Educational purposes
 * - Security research
 * - Testing security tools
 * - Academic studies
 * 
 * NEVER use this code in production environments!
 */

const mysql = require('mysql');
const sqlite3 = require('sqlite3').verbose();
const express = require('express');
const app = express();

// ============================================================================
// BASIC STRING CONCATENATION VULNERABILITIES
// ============================================================================

function vulnerableLogin1(username, password) {
    // VULNERABLE: Direct string concatenation
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results.length > 0);
            }
        });
    });
}

function vulnerableLogin2(username, password) {
    // VULNERABLE: Template literals
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results.length > 0);
            }
        });
    });
}

function vulnerableLogin3(username, password) {
    // VULNERABLE: String concatenation with variables
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    
    const db = new sqlite3.Database('./users.db');
    
    return new Promise((resolve, reject) => {
        db.get(query, (error, row) => {
            db.close();
            if (error) {
                reject(error);
            } else {
                resolve(row !== undefined);
            }
        });
    });
}

// ============================================================================
// SEARCH FUNCTIONALITY VULNERABILITIES
// ============================================================================

function vulnerableSearch1(searchTerm) {
    // VULNERABLE: String concatenation in LIKE
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results);
            }
        });
    });
}

function vulnerableSearch2(searchTerm) {
    // VULNERABLE: Template literals in LIKE
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results);
            }
        });
    });
}

// ============================================================================
// DATA MANIPULATION VULNERABILITIES
// ============================================================================

function vulnerableInsert(name, email) {
    // VULNERABLE: String concatenation in INSERT
    const query = "INSERT INTO users (name, email) VALUES ('" + name + "', '" + email + "')";
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results.affectedRows > 0);
            }
        });
    });
}

function vulnerableUpdate(userId, newName) {
    // VULNERABLE: String concatenation in UPDATE
    const query = "UPDATE users SET name = '" + newName + "' WHERE id = " + userId;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results.affectedRows > 0);
            }
        });
    });
}

function vulnerableDelete(userId) {
    // VULNERABLE: String concatenation in DELETE
    const query = "DELETE FROM users WHERE id = " + userId;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results.affectedRows > 0);
            }
        });
    });
}

// ============================================================================
// EXPRESS.JS ROUTE VULNERABILITIES
// ============================================================================

app.post('/vulnerable_login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE: Direct string concatenation
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    connection.query(query, (error, results) => {
        connection.end();
        if (error) {
            res.status(500).json({ error: 'Database error' });
        } else if (results.length > 0) {
            res.json({ status: 'success', message: 'Login successful' });
        } else {
            res.json({ status: 'error', message: 'Invalid credentials' });
        }
    });
});

app.get('/vulnerable_search', (req, res) => {
    const searchTerm = req.query.q || '';
    
    // VULNERABLE: String concatenation in LIKE
    const query = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    connection.query(query, (error, results) => {
        connection.end();
        if (error) {
            res.status(500).json({ error: 'Database error' });
        } else {
            res.json({ products: results });
        }
    });
});

app.get('/vulnerable_user/:userId', (req, res) => {
    const userId = req.params.userId;
    
    // VULNERABLE: String concatenation with path parameter
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    connection.query(query, (error, results) => {
        connection.end();
        if (error) {
            res.status(500).json({ error: 'Database error' });
        } else if (results.length > 0) {
            res.json({ user: results[0] });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

// ============================================================================
// NO-SQL INJECTION VULNERABILITIES (MongoDB)
// ============================================================================

const { MongoClient } = require('mongodb');

function mongodbVulnerableQuery(username) {
    // VULNERABLE: NoSQL injection in MongoDB
    const query = `{"username": "${username}"}`;
    
    return new Promise(async (resolve, reject) => {
        try {
            const client = new MongoClient('mongodb://localhost:27017');
            await client.connect();
            
            const db = client.db('testdb');
            const collection = db.collection('users');
            
            const user = await collection.findOne(JSON.parse(query));
            await client.close();
            
            resolve(user);
        } catch (error) {
            reject(error);
        }
    });
}

function mongodbVulnerableAuthentication(username, password) {
    // VULNERABLE: Authentication bypass in MongoDB
    const query = `{"username": "${username}", "password": "${password}"}`;
    
    return new Promise(async (resolve, reject) => {
        try {
            const client = new MongoClient('mongodb://localhost:27017');
            await client.connect();
            
            const db = client.db('testdb');
            const collection = db.collection('users');
            
            const user = await collection.findOne(JSON.parse(query));
            await client.close();
            
            resolve(user !== null);
        } catch (error) {
            reject(error);
        }
    });
}

// ============================================================================
// INPUT VALIDATION BYPASSES
// ============================================================================

function bypassSimpleValidation(userInput) {
    // VULNERABLE: Inadequate validation
    if (userInput.includes("'") || userInput.includes(";")) {
        return "Invalid input";
    }
    
    // Still vulnerable to other injection techniques
    const query = "SELECT * FROM users WHERE id = " + userInput;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results);
            }
        });
    });
}

function bypassRegexValidation(userInput) {
    // VULNERABLE: Regex can be bypassed
    if (!/^[0-9]+$/.test(userInput)) {
        return "Invalid input";
    }
    
    // Still vulnerable to numeric injection
    const query = "SELECT * FROM users WHERE id = " + userInput + " OR 1=1";
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(query, (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results);
            }
        });
    });
}

// ============================================================================
// COOKIE AND SESSION VULNERABILITIES
// ============================================================================

app.get('/vulnerable_cookie', (req, res) => {
    const userId = req.cookies.userId;
    
    // VULNERABLE: Cookie injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    connection.query(query, (error, results) => {
        connection.end();
        if (error) {
            res.status(500).json({ error: 'Database error' });
        } else if (results.length > 0) {
            res.json({ user: results[0] });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

app.get('/vulnerable_session', (req, res) => {
    const userId = req.session.userId;
    
    // VULNERABLE: Session injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    connection.query(query, (error, results) => {
        connection.end();
        if (error) {
            res.status(500).json({ error: 'Database error' });
        } else if (results.length > 0) {
            res.json({ user: results[0] });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    });
});

// ============================================================================
// BATCH OPERATIONS VULNERABILITIES
// ============================================================================

function vulnerableBatchInsert(names) {
    // VULNERABLE: Batch operations with string concatenation
    const queries = names.map(name => "INSERT INTO users (name) VALUES ('" + name + "')");
    
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'password',
        database: 'testdb'
    });
    
    return new Promise((resolve, reject) => {
        connection.query(queries.join(';'), (error, results) => {
            connection.end();
            if (error) {
                reject(error);
            } else {
                resolve(results);
            }
        });
    });
}

// ============================================================================
// MAIN SERVER SETUP
// ============================================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Vulnerable server running on port ${PORT}`);
    console.log('WARNING: This server is intentionally vulnerable!');
    console.log('Use only for educational and research purposes.');
});

// Export functions for testing
module.exports = {
    vulnerableLogin1,
    vulnerableLogin2,
    vulnerableLogin3,
    vulnerableSearch1,
    vulnerableSearch2,
    vulnerableInsert,
    vulnerableUpdate,
    vulnerableDelete,
    mongodbVulnerableQuery,
    mongodbVulnerableAuthentication,
    bypassSimpleValidation,
    bypassRegexValidation,
    vulnerableBatchInsert
}; 