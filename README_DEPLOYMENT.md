# SQL Injection Scanner - Google Cloud Deployment

This repository contains a professional-grade SQL injection vulnerability scanner with SonarQube integration, ready for deployment to Google Cloud Platform.

## Quick Start

### Option 1: Automated Deployment Script

1. **Install Google Cloud CLI**:
   ```bash
   brew install --cask google-cloud-sdk
   ```

2. **Login and Set Project**:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

3. **Run Deployment Script**:
   ```bash
   ./deploy.sh
   ```

### Option 2: Manual Deployment

Follow the detailed guide in `DEPLOYMENT_GUIDE.md`.

### Option 3: CI/CD with Cloud Build

```bash
gcloud builds submit --config cloudbuild.yaml
```

## What Gets Deployed

- **Backend**: Flask API with enhanced SQL injection detection
- **Frontend**: React application with modern UI
- **Features**: SonarQube integration, compliance reporting, vulnerability scoring

## Configuration Files

- `sql_injection/app.yaml` - Backend App Engine configuration
- `sql_injection/requirements.txt` - Python dependencies
- `frontend/app.yaml` - Frontend App Engine configuration
- `frontend/src/config.js` - API endpoint configuration
- `cloudbuild.yaml` - CI/CD configuration
- `deploy.sh` - Automated deployment script

## Security Features

✅ **Industry-Standard Detection**: Based on SonarQube's SecurityStandards  
✅ **Compliance Mapping**: CWE-89, OWASP Top 10 2021  
✅ **Professional Reporting**: Word documents, JSON export, SonarQube format  
✅ **Authentication**: JWT-based security  
✅ **HTTPS**: Automatic SSL certificates  

## Technology Stack

- **Backend**: Flask, Python AST analysis, SonarQube standards
- **Frontend**: React, TypeScript, Tailwind CSS
- **Cloud**: Google App Engine, Cloud Build
- **Security**: JWT authentication, CORS configuration

## Support

For deployment issues, check:
- `DEPLOYMENT_GUIDE.md` for detailed instructions
- Google Cloud Console for error logs
- `gcloud app logs tail` for real-time logs

## License

This project is created for educational and professional security testing purposes. 