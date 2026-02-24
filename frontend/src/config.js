const DEFAULT_DEV_API_BASE_URL = 'http://localhost:5001';
const DEFAULT_PROD_API_BASE_URL = 'https://api-dot-sql-scanner-thesis.de.r.appspot.com';

const nodeEnv = process.env.NODE_ENV || 'development';
const fallback = nodeEnv === 'production' ? DEFAULT_PROD_API_BASE_URL : DEFAULT_DEV_API_BASE_URL;

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || fallback;

export default { API_BASE_URL };
