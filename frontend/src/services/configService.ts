import config from '../config.js';

export interface ScannerConfig {
  scanners: {
    sql_injection: number;
  };
  description: string;
}

export const fetchScannerConfig = async (): Promise<ScannerConfig> => {
  try {
    const response = await fetch(`${config.API_BASE_URL}/api/scanner-config`);
    if (!response.ok) {
      throw new Error('Failed to fetch scanner configuration');
    }
    return await response.json();
  } catch (error) {
    console.error('Error fetching scanner config:', error);
    // Return default config if fetch fails
    return {
      scanners: {
        sql_injection: 1
      },
      description: 'Default configuration'
    };
  }
};

export const isScannerEnabled = (config: ScannerConfig, scannerType: string): boolean => {
  const scannerKey = scannerType === 'sql' ? 'sql_injection' : '';
  
  if (!scannerKey) return false;
  return config.scanners[scannerKey as keyof typeof config.scanners] === 1;
}; 