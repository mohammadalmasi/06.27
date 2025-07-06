# Google Cloud Platform Deployment Guide

This guide will help you deploy both the Flask backend and React frontend to Google Cloud Platform.

## Prerequisites

1. **Google Cloud Account**: Create a Google Cloud account if you don't have one
2. **Google Cloud SDK**: Install the Google Cloud CLI
3. **Project Setup**: Create a new Google Cloud project

## Step 1: Install Google Cloud CLI

### macOS (using Homebrew):
```bash
brew install --cask google-cloud-sdk
```

### Or download directly:
```bash
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
```

## Step 2: Initialize Google Cloud

```bash
# Login to Google Cloud
gcloud auth login

# Create a new project (replace 'my-sql-scanner' with your preferred project ID)
gcloud projects create my-sql-scanner --name="SQL Injection Scanner"

# Set the project
gcloud config set project my-sql-scanner

# Enable required APIs
gcloud services enable appengine.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

## Step 3: Deploy the Backend (Flask API)

1. **Navigate to the backend directory:**
```bash
cd sql_injection
```

2. **Update the App Engine configuration:**
- Edit `app.yaml` and update the `JWT_SECRET_KEY` to a secure value
- Change the production JWT secret key to something secure

3. **Deploy the backend:**
```bash
gcloud app deploy app.yaml
```

4. **Get the backend URL:**
```bash
gcloud app describe --format="value(defaultHostname)"
```
This will return something like: `my-sql-scanner.appspot.com`

## Step 4: Update Frontend Configuration

1. **Navigate to the frontend directory:**
```bash
cd ../frontend
```

2. **Update the API endpoint:**
- Edit `src/config.js`
- Replace `https://your-app-name.appspot.com` with your actual backend URL:
```javascript
const config = {
  development: {
    API_BASE_URL: 'http://localhost:5001',
  },
  production: {
    API_BASE_URL: 'https://my-sql-scanner.appspot.com', // Replace with your actual URL
  },
};
```

## Step 5: Deploy the Frontend (React App)

1. **Install dependencies:**
```bash
npm install
```

2. **Build the React app:**
```bash
npm run build
```

3. **Deploy the frontend:**
```bash
gcloud app deploy app.yaml
```

## Step 6: Configure Custom Domain (Optional)

If you want to use a custom domain:

```bash
# Add custom domain
gcloud app domain-mappings create yourdomain.com

# Configure SSL certificate
gcloud app ssl-certificates create --domains=yourdomain.com
```

## Step 7: Verify Deployment

1. **Check the backend:**
```bash
curl https://my-sql-scanner.appspot.com/user
```

2. **Check the frontend:**
Open your browser and navigate to your App Engine URL

## Environment Variables

Make sure to set these environment variables in production:

### Backend (app.yaml):
```yaml
env_variables:
  JWT_SECRET_KEY: "your-super-secret-jwt-key-change-this-in-production"
  FLASK_ENV: "production"
```

### Frontend (config.js):
```javascript
production: {
  API_BASE_URL: 'https://your-actual-backend-url.appspot.com',
}
```

## Security Considerations

1. **JWT Secret**: Use a strong, random JWT secret key
2. **CORS**: The backend is configured to allow all origins. In production, you may want to restrict this to your frontend domain
3. **API Keys**: Store any API keys in Google Cloud Secret Manager
4. **HTTPS**: App Engine automatically provides HTTPS

## Troubleshooting

### Common Issues:

1. **CORS Errors**: 
   - Make sure the frontend config points to the correct backend URL
   - Check that CORS is properly configured in the Flask app

2. **404 Errors**:
   - Verify the API endpoints are correctly mapped
   - Check that the backend is deployed and running

3. **Authentication Issues**:
   - Ensure JWT secret keys match between environments
   - Check that tokens are being passed correctly

### Check Logs:
```bash
# Backend logs
gcloud app logs tail -s default

# View deployment status
gcloud app versions list
```

## Scaling and Monitoring

1. **Auto-scaling**: App Engine automatically scales based on traffic
2. **Monitoring**: Use Google Cloud Console to monitor your app
3. **Logging**: All logs are available in Google Cloud Logging

## Cost Optimization

1. **Free Tier**: App Engine offers a generous free tier
2. **Scaling**: Configure min/max instances in app.yaml
3. **Monitoring**: Set up billing alerts to monitor costs

## Deployment Commands Summary

```bash
# Deploy backend
cd sql_injection
gcloud app deploy app.yaml

# Deploy frontend
cd ../frontend
npm run build
gcloud app deploy app.yaml

# View deployed app
gcloud app browse
```

## Alternative: Using Cloud Build (CI/CD)

For automated deployments, you can set up Cloud Build:

1. **Create cloudbuild.yaml**:
```yaml
steps:
  # Build frontend
  - name: 'node:18'
    entrypoint: 'npm'
    args: ['install']
    dir: 'frontend'
  
  - name: 'node:18'
    entrypoint: 'npm'
    args: ['run', 'build']
    dir: 'frontend'
  
  # Deploy backend
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: 'gcloud'
    args: ['app', 'deploy', 'sql_injection/app.yaml']
  
  # Deploy frontend
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: 'gcloud'
    args: ['app', 'deploy', 'frontend/app.yaml']
```

2. **Trigger build**:
```bash
gcloud builds submit --config cloudbuild.yaml
```

## Support

If you encounter any issues:

1. Check the Google Cloud Console for error messages
2. Review the deployment logs
3. Verify all configuration files are correct
4. Ensure all required APIs are enabled

Your SQL Injection Scanner is now deployed to Google Cloud Platform!

## URLs After Deployment

- **Backend API**: `https://my-sql-scanner.appspot.com`
- **Frontend App**: `https://my-sql-scanner.appspot.com` (same URL if using single service)
- **Admin Console**: `https://console.cloud.google.com/appengine`

Remember to replace `my-sql-scanner` with your actual project ID throughout this guide. 