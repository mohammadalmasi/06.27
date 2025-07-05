# SQL Injection Scanner with React Frontend

A comprehensive SQL injection vulnerability detection tool with a modern React frontend and Flask backend API.

## 🎯 Features

- **Modern React UI**: Comprehensive, responsive design with Tailwind CSS
- **Multiple Input Methods**: GitHub URL scanning, file upload, and direct code input
- **Advanced Detection**: AST-based analysis for accurate vulnerability detection
- **Detailed Reports**: Interactive results with code highlighting and remediation suggestions
- **Multi-Language Support**: Python, JavaScript, PHP, Java, C# support
- **Real-time Scanning**: Instant vulnerability analysis with confidence scores

## 🏗️ Project Structure

```
06.27/
├── frontend/                    # React TypeScript frontend
│   ├── src/
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/             # Main application pages
│   │   ├── types/             # TypeScript type definitions
│   │   └── services/          # API service functions
│   ├── public/                # Static assets
│   └── package.json          # Frontend dependencies
├── sql_injection/             # Flask backend
│   ├── app.py                # Main Flask application
│   ├── sql_injection_detector.py  # Core detection engine
│   ├── vulnerable_code_examples/  # Test datasets
│   └── results/              # Generated reports
└── venv/                     # Python virtual environment
```

## 🚀 Quick Start

### Prerequisites

- Node.js 16+ and npm
- Python 3.8+
- Git

### Backend Setup

1. **Activate the virtual environment:**
   ```bash
   cd 06.27
   source venv/bin/activate
   ```

2. **Install Python dependencies:**
   ```bash
   pip install flask flask-cors requests beautifulsoup4 python-docx
   ```

3. **Start the Flask backend:**
   ```bash
   cd sql_injection
   python app.py
   ```
   
   The backend will run on `http://localhost:5000`

### Frontend Setup

1. **Navigate to frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the React development server:**
   ```bash
   npm start
   ```
   
   The frontend will run on `http://localhost:3000`

## 🌐 Usage

### Web Interface

1. Open your browser to `http://localhost:3000`
2. Choose your scanning method:
   - **GitHub URL**: Enter a direct link to a Python file
   - **File Upload**: Drag and drop or select a source code file
   - **Paste Code**: Directly paste your code for analysis
3. Click "Start Security Scan"
4. Review the detailed vulnerability report

### API Endpoints

#### POST `/api/scan`

Scan code for SQL injection vulnerabilities.

**Request:**
```bash
curl -X POST http://localhost:5000/api/scan \
  -F "code=import sqlite3; query = 'SELECT * FROM users WHERE id = ' + user_id"
```

**Response:**
```json
{
  "vulnerabilities": [
    {
      "file_path": "temp_paste_20241227_143022.py",
      "line_number": 1,
      "vulnerability_type": "SQL_INJECTION_CONCATENATION",
      "description": "String concatenation used in SQL query",
      "severity": "HIGH",
      "code_snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
      "remediation": "Use parameterized queries instead of string concatenation",
      "confidence": 0.8
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "high_severity": 1,
    "medium_severity": 0,
    "low_severity": 0
  },
  "scan_info": {
    "scan_timestamp": "2024-12-27T14:30:22.123456",
    "input_type": "code",
    "file_name": "pasted_code.py"
  }
}
```

## 🔍 Detection Capabilities

### Vulnerability Types

- String concatenation vulnerabilities
- Dynamic query construction
- Unsafe parameter binding
- NoSQL injection patterns
- Framework-specific vulnerabilities
- Input validation bypass
- Authentication bypass
- Boolean-based blind injection
- Time-based blind injection
- Union-based injection
- Error-based injection
- Second-order SQL injection

### Supported Technologies

**Languages:**
- Python
- JavaScript/TypeScript
- PHP
- Java
- C#

**Frameworks:**
- Flask/Django
- Express.js
- Spring Boot
- ASP.NET
- Laravel

**Databases:**
- SQLite
- MySQL
- PostgreSQL
- MongoDB
- SQL Server

## 🛡️ Security Best Practices

### Recommended Mitigation Strategies

1. **Use Parameterized Queries**
   ```python
   # ❌ Vulnerable
   query = f"SELECT * FROM users WHERE id = {user_id}"
   
   # ✅ Secure
   cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   ```

2. **Input Validation**
   ```python
   # ✅ Validate input
   if user_id.isdigit():
       user_id = int(user_id)
   else:
       raise ValueError("Invalid user ID")
   ```

3. **Use ORM Frameworks**
   ```python
   # ✅ SQLAlchemy ORM
   user = session.query(User).filter_by(id=user_id).first()
   ```

4. **Principle of Least Privilege**
   - Use database accounts with minimal necessary permissions
   - Avoid using administrative database accounts for applications

## 🧪 Testing

### Running Tests

```bash
# Backend tests
cd sql_injection
python -m pytest tests/

# Frontend tests
cd frontend
npm test
```

### Example Vulnerable Code

Test the scanner with these vulnerable patterns:

```python
# String concatenation
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)

# Format string
def search_products(search_term):
    query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(search_term)
    return execute_query(query)

# F-string
def get_orders(status):
    query = f"SELECT * FROM orders WHERE status = '{status}'"
    return execute_query(query)
```

## 📊 Development

### Frontend Development

```bash
cd frontend

# Start development server with hot reload
npm start

# Build for production
npm run build

# Run linting
npm run lint

# Run type checking
npm run type-check
```

### Backend Development

```bash
cd sql_injection

# Run with debug mode
python app.py

# Run vulnerability scanner directly
python sql_injection_detector.py

# Generate test reports
python -c "from app import scan_code_file; scan_code_file('test.py')"
```

## 🚀 Deployment

### Production Build

1. **Build the React frontend:**
   ```bash
   cd frontend
   npm run build
   ```

2. **Serve static files with Flask:**
   ```python
   # Add to app.py
   from flask import send_from_directory

   @app.route('/', defaults={'path': ''})
   @app.route('/<path:path>')
   def serve_react_app(path):
       if path != "" and os.path.exists(app.static_folder + '/' + path):
           return send_from_directory(app.static_folder, path)
       else:
           return send_from_directory(app.static_folder, 'index.html')
   ```

3. **Configure production server:**
   ```bash
   pip install gunicorn
   gunicorn --bind 0.0.0.0:8000 app:app
   ```

## ⚠️ Security Notice

**Educational Use Only**: This tool is designed for security research, education, and authorized penetration testing. Always ensure you have proper authorization before testing any system or application. The developers are not responsible for any misuse of this tool.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Backend web framework
- [React](https://reactjs.org/) - Frontend library
- [Tailwind CSS](https://tailwindcss.com/) - CSS framework
- [Lucide React](https://lucide.dev/) - Icon library
- Python AST module for code analysis 