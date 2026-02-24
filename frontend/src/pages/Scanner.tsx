import React, { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { 
  Upload, 
  Link as LinkIcon, 
  Code, 
  AlertTriangle, 
  Loader2,
  FileText,
  X,
  Shield,
  Bug,
  CheckCircle2,
} from 'lucide-react';
import toast from 'react-hot-toast';
import config from '../config.js';
import { fetchScannerConfig, isScannerEnabled, ScannerConfig } from '../services/configService';

interface ScanInput {
  type: 'url' | 'file' | 'code';
  content: string;
  filename?: string;
}

type ScannerType = 'sql' | 'xss' | 'command' | 'csrf';

type IconComponent = React.ComponentType<{ className?: string }>;

const Scanner: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'url' | 'file' | 'code'>('code');
  const [scannerType, setScannerType] = useState<ScannerType>('sql');
  const [isScanning, setIsScanning] = useState(false);
  const [analysisMode, setAnalysisMode] = useState<'static' | 'ml'>('static');
  const [scannerConfig, setScannerConfig] = useState<ScannerConfig | null>(null);
  const [isLoadingConfig, setIsLoadingConfig] = useState(true);
  const [scanInput, setScanInput] = useState<ScanInput>({
    type: 'code',
    content: '',
    filename: ''
  });
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);

  // Fetch scanner configuration on component mount
  useEffect(() => {
    const loadConfig = async () => {
      try {
        const config = await fetchScannerConfig();
        setScannerConfig(config);
        
        // Set the first enabled scanner as default
        if (isScannerEnabled(config, 'sql')) {
          setScannerType('sql');
        } else if (isScannerEnabled(config, 'xss')) {
          setScannerType('xss');
        } else if (isScannerEnabled(config, 'command')) {
          setScannerType('command');
        } else if (isScannerEnabled(config, 'csrf')) {
          setScannerType('csrf');
        }
      } catch (error) {
        console.error('Failed to load scanner configuration:', error);
        toast.error('Failed to load scanner configuration');
      } finally {
        setIsLoadingConfig(false);
      }
    };
    
    loadConfig();
  }, []);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const validFiles = acceptedFiles.filter(file => {
      const validExtensions = ['.py', '.js', '.php', '.java', '.cs', '.ts', '.jsx', '.tsx'];
      const hasValidExtension = validExtensions.some(ext => file.name.toLowerCase().endsWith(ext));
      
      if (!hasValidExtension) {
        toast.error(`${file.name} is not a supported file type`);
        return false;
      }
      
      if (file.size > 2 * 1024 * 1024) { // 2MB limit
        toast.error(`${file.name} is too large. Maximum size is 2MB`);
        return false;
      }
      
      return true;
    });

    if (validFiles.length > 0) {
      setUploadedFiles(validFiles);
      const file = validFiles[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        setScanInput({
          type: 'file',
          content: e.target?.result as string,
          filename: file.name
        });
      };
      reader.readAsText(file);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/plain': ['.py', '.js', '.php', '.java', '.cs', '.ts', '.jsx', '.tsx'],
      'application/x-python': ['.py'],
      'application/javascript': ['.js'],
      'application/x-php': ['.php'],
      'text/x-java-source': ['.java'],
      'text/x-csharp': ['.cs'],
      'application/typescript': ['.ts'],
      'text/jsx': ['.jsx'],
      'text/tsx': ['.tsx']
    },
    multiple: false,
    maxSize: 2 * 1024 * 1024 // 2MB
  });

  const handleInputChange = (value: string) => {
    setScanInput(prev => ({ ...prev, content: value }));
  };

  const handleScanKeyDown = (e: React.KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      if (canScan()) {
        handleScan();
      }
    }
  };

  const handleTabChange = (tab: 'url' | 'file' | 'code') => {
    setActiveTab(tab);
    setScanInput(prev => ({ ...prev, type: tab }));
    setUploadedFiles([]);
  };

  const removeFile = () => {
    setUploadedFiles([]);
    setScanInput(prev => ({ ...prev, content: '', filename: '' }));
  };

  const handleScan = async () => {
    if (!scanInput.content.trim()) {
      toast.error('Please provide code to scan');
      return;
    }

    setIsScanning(true);
    
    try {
      // Prepare JSON payload for the appropriate API endpoint
      const payload: any = {};
      
      if (scanInput.type === 'url') {
        payload.url = scanInput.content;
      } else if (scanInput.type === 'file') {
        payload.code = scanInput.content;
      } else {
        payload.code = scanInput.content;
      }

      // Headers for API requests
      const headers: HeadersInit = {
        'Content-Type': 'application/json'
      };

      let results: any;
      if (analysisMode === 'static') {
        // Choose the appropriate API endpoint based on scanner type
        let endpoint: string;
        if (scannerType === 'sql') {
          endpoint = '/api/scan-sql-injection';
        } else if (scannerType === 'xss') {
          endpoint = '/api/scan-xss';
        } else if (scannerType === 'command') {
          endpoint = '/api/scan-command-injection';
        } else if (scannerType === 'csrf') {
          endpoint = '/api/scan-csrf';
        } else {
          throw new Error('Invalid scanner type');
        }

        const response = await fetch(`${config.API_BASE_URL}${endpoint}`, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'Scan failed');
        }
        results = await response.json();
      } else {
        const mlPayload: any = {
          type: scannerType,
          code: payload.code || payload.url,
          filename: scanInput.filename || (scannerType + '.py')
        };

        const response = await fetch(`${config.API_BASE_URL}/api/scan-ml`, {
          method: 'POST',
          headers,
          body: JSON.stringify(mlPayload)
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || 'ML scan failed');
        }
        results = await response.json();
      }
      
      // Store results in localStorage for the Results page
      localStorage.setItem('scanResults', JSON.stringify({...results, scannerType, analysisMode}));
      localStorage.setItem('scanInput', JSON.stringify(scanInput));
      
      let vulnerabilityType: string;
      if (scannerType === 'sql') {
        vulnerabilityType = 'SQL injection vulnerabilities';
      } else if (scannerType === 'xss') {
        vulnerabilityType = 'XSS vulnerabilities';
      } else if (scannerType === 'command') {
        vulnerabilityType = 'Command injection vulnerabilities';
      } else if (scannerType === 'csrf') {
        vulnerabilityType = 'CSRF vulnerabilities';
      } else {
        vulnerabilityType = 'vulnerabilities';
      }
      if (analysisMode === 'static') {
        toast.success(`Scan completed! Found ${results.total_issues || 0} ${vulnerabilityType}`);
      } else {
        toast.success('ML analysis completed');
      }
      navigate('/results');
      
    } catch (error) {
      console.error('Scan error:', error);
      toast.error(error instanceof Error ? error.message : 'Scan failed. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const isValidUrl = (url: string) => {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  };

  const canScan = () => {
    if (isScanning) return false;
    
    switch (activeTab) {
      case 'url':
        return scanInput.content.trim() && isValidUrl(scanInput.content);
      case 'file':
        return uploadedFiles.length > 0 && scanInput.content.trim();
      case 'code':
        return scanInput.content.trim();
      default:
        return false;
    }
  };

  const getScannerTitle = () => {
    if (scannerType === 'sql') {
      return 'SQL Injection Scanner';
    } else if (scannerType === 'xss') {
      return 'XSS Scanner';
    } else if (scannerType === 'command') {
      return 'Command Injection Scanner';
    } else if (scannerType === 'csrf') {
      return 'CSRF Scanner';
    }
    return '';
  };

  const getScannerMeta = (type: ScannerType): { label: string; description: string; Icon: IconComponent } => {
    switch (type) {
      case 'sql':
        return {
          label: 'SQL Injection',
          description: 'Find unsafe SQL query construction patterns and injection sinks.',
          Icon: Bug,
        };
      case 'xss':
        return {
          label: 'XSS',
          description: 'Detect potentially unsafe HTML/JS rendering and injection points.',
          Icon: Shield,
        };
      case 'command':
        return {
          label: 'Command Injection',
          description: 'Identify dangerous OS command execution patterns and tainted inputs.',
          Icon: AlertTriangle,
        };
      case 'csrf':
        return {
          label: 'CSRF',
          description: 'Spot missing CSRF defenses in state-changing requests and forms.',
          Icon: Shield,
        };
      default:
        return {
          label: 'Scanner',
          description: 'Run a security scan.',
          Icon: Shield,
        };
    }
  };

  const getInputHeader = () => {
    if (activeTab === 'code') return { title: 'Paste code', subtitle: 'Paste a snippet or a full file. Press Ctrl/⌘ + Enter to scan.' };
    if (activeTab === 'file') return { title: 'Upload a file', subtitle: 'Upload a single source file (max 2MB). You can preview it before scanning.' };
    return { title: 'Scan from GitHub URL', subtitle: 'Paste a direct link to a file on GitHub.' };
  };

  // Show loading state while fetching configuration
  if (isLoadingConfig) {
    return (
      <div className="min-h-screen py-6">
        <div className="w-full px-4 sm:px-6 lg:px-8 2xl:px-12">
          <div className="card p-8 text-center">
            <Loader2 className="h-12 w-12 animate-spin mx-auto mb-4 text-primary-600" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">Loading Scanner Configuration</h2>
            <p className="text-gray-600">Please wait while we load the available scanners...</p>
          </div>
        </div>
      </div>
    );
  }

  // Show message if no scanners are enabled
  if (!scannerConfig || !Object.values(scannerConfig.scanners).some(enabled => enabled === 1)) {
    return (
      <div className="min-h-screen py-6">
        <div className="w-full px-4 sm:px-6 lg:px-8 2xl:px-12">
          <div className="card p-8 text-center">
            <AlertTriangle className="h-16 w-16 text-yellow-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-gray-900 mb-2">No Scanners Available</h2>
            <p className="text-gray-600 mb-4">
              All scanners are currently disabled. Please contact your administrator to enable scanners.
            </p>
            <button
              onClick={() => navigate('/scanner')}
              className="btn-primary"
            >
              Back to Scanner
            </button>
          </div>
        </div>
      </div>
    );
  }

  const meta = getScannerMeta(scannerType);
  const inputHeader = getInputHeader();
  const isUrl = activeTab === 'url';
  const urlValue = isUrl ? scanInput.content.trim() : '';
  const urlIsValid = isUrl ? (urlValue.length > 0 && isValidUrl(urlValue)) : false;

  return (
    <div className="min-h-screen py-6">
      <div className="w-full px-4 sm:px-6 lg:px-8 2xl:px-12">
        <>
          {/* Header */}
          <div className="mb-4 flex flex-col gap-2">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h1 className="text-2xl md:text-3xl font-bold text-slate-900 leading-tight">
                  {getScannerTitle()}
                </h1>
                <p className="mt-1 text-sm md:text-base text-slate-600">
                  {meta.description}
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            {/* Main input */}
            <div className="order-1 lg:order-2 lg:col-span-8">
              <div className="card">
                <div className="card-header">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <h2 className="text-base font-semibold text-slate-900">{inputHeader.title}</h2>
                      <p className="text-sm text-slate-600">{inputHeader.subtitle}</p>
                    </div>
                    {(activeTab === 'code' || activeTab === 'url') && scanInput.content.trim().length > 0 && (
                      <button
                        type="button"
                        onClick={() => setScanInput(prev => ({ ...prev, content: '' }))}
                        className="btn-secondary py-2 px-3 text-sm"
                        disabled={isScanning}
                        title="Clear"
                      >
                        <span className="inline-flex items-center gap-2">
                          <X className="h-4 w-4" />
                          Clear
                        </span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Tabs */}
                <div className="flex border-b border-slate-200/80 bg-white">
                  <button
                    onClick={() => handleTabChange('code')}
                    className={`flex-1 py-3 px-4 text-center font-medium transition-colors duration-200 ${
                      activeTab === 'code'
                        ? 'bg-primary-50 text-primary-700 border-b-2 border-primary-600'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                    type="button"
                  >
                    <Code className="h-5 w-5 mx-auto mb-1" />
                    Paste Code
                  </button>
                  <button
                    onClick={() => handleTabChange('file')}
                    className={`flex-1 py-3 px-4 text-center font-medium transition-colors duration-200 ${
                      activeTab === 'file'
                        ? 'bg-primary-50 text-primary-700 border-b-2 border-primary-600'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                    type="button"
                  >
                    <Upload className="h-5 w-5 mx-auto mb-1" />
                    Upload File
                  </button>
                  <button
                    onClick={() => handleTabChange('url')}
                    className={`flex-1 py-3 px-4 text-center font-medium transition-colors duration-200 ${
                      activeTab === 'url'
                        ? 'bg-primary-50 text-primary-700 border-b-2 border-primary-600'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                    }`}
                    type="button"
                  >
                    <LinkIcon className="h-5 w-5 mx-auto mb-1" />
                    GitHub URL
                  </button>
                </div>

                {/* Tab content */}
                <div className="card-body space-y-4">
                  {activeTab === 'url' && (
                    <div className="space-y-2">
                      <label className="block text-sm font-medium text-slate-700">
                        GitHub file URL
                      </label>
                      <div className="relative">
                        <input
                          type="url"
                          value={scanInput.content}
                          onChange={(e) => handleInputChange(e.target.value)}
                          onKeyDown={handleScanKeyDown}
                          placeholder="https://github.com/user/repo/blob/main/file.py"
                          className={`input-field pr-10 ${urlValue.length > 0 && !urlIsValid ? 'ring-2 ring-danger-300 border-danger-300' : ''}`}
                        />
                        <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                          {urlValue.length === 0 ? null : urlIsValid ? (
                            <CheckCircle2 className="h-5 w-5 text-success-600" />
                          ) : (
                            <AlertTriangle className="h-5 w-5 text-danger-600" />
                          )}
                        </div>
                      </div>
                      <p className={`text-sm ${urlValue.length === 0 ? 'text-slate-500' : urlIsValid ? 'text-success-700' : 'text-danger-700'}`}>
                        {urlValue.length === 0
                          ? 'Paste a direct link to a file (GitHub “blob” URL is OK).'
                          : urlIsValid
                          ? 'Looks good — ready to scan.'
                          : 'This doesn’t look like a valid URL.'}
                      </p>
                    </div>
                  )}

                  {activeTab === 'file' && (
                    <div className="space-y-3">
                      <label className="block text-sm font-medium text-slate-700">
                        Upload source file
                      </label>

                      {uploadedFiles.length === 0 ? (
                        <div
                          {...getRootProps()}
                          className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors duration-200 ${
                            isDragActive
                              ? 'border-primary-400 bg-primary-50'
                              : 'border-slate-300 hover:border-slate-400 bg-white'
                          }`}
                        >
                          <input {...getInputProps()} />
                          <Upload className="h-12 w-12 text-slate-400 mx-auto mb-4" />
                          <p className="text-base font-medium text-slate-800 mb-1">
                            {isDragActive
                              ? 'Drop your file here'
                              : 'Drag and drop your file here, or click to browse'}
                          </p>
                          <p className="text-sm text-slate-500">
                            Supports .py, .js, .php, .java, .cs, .ts, .jsx, .tsx (max 2MB)
                          </p>
                        </div>
                      ) : (
                        <div className="space-y-3">
                          <div className="flex items-center justify-between rounded-xl ring-1 ring-slate-200/70 bg-slate-50/60 px-4 py-3">
                            <div className="flex items-center gap-3 min-w-0">
                              <FileText className="h-6 w-6 text-primary-700 shrink-0" />
                              <div className="min-w-0">
                                <p className="font-medium text-slate-900 truncate">{uploadedFiles[0].name}</p>
                                <p className="text-sm text-slate-500">
                                  {(uploadedFiles[0].size / 1024).toFixed(1)} KB
                                </p>
                              </div>
                            </div>
                            <button
                              onClick={removeFile}
                              className="btn-secondary py-2 px-3"
                              type="button"
                              disabled={isScanning}
                              title="Remove file"
                            >
                              <span className="inline-flex items-center gap-2">
                                <X className="h-4 w-4" />
                                Remove
                              </span>
                            </button>
                          </div>

                          <div>
                            <div className="flex items-center justify-between mb-2">
                              <p className="text-sm font-medium text-slate-700">Preview</p>
                              <p className="text-xs text-slate-500">Read-only</p>
                            </div>
                            <textarea
                              value={scanInput.content}
                              readOnly
                              rows={14}
                              className="textarea-field font-mono text-sm min-h-[320px] bg-slate-50/60"
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab === 'code' && (
                    <div className="space-y-2">
                      <label className="block text-sm font-medium text-slate-700">
                        Source code
                      </label>
                      <textarea
                        value={scanInput.content}
                        onChange={(e) => handleInputChange(e.target.value)}
                        onKeyDown={handleScanKeyDown}
                        placeholder={scannerType === 'sql' 
                          ? "# Paste your code here (SQL injection analysis)..."
                          : scannerType === 'xss'
                          ? "# Paste your code here (XSS analysis)..."
                          : scannerType === 'command'
                          ? "# Paste your code here (command injection analysis)..."
                          : "# Paste your code here (CSRF analysis)..."
                        }
                        rows={18}
                        className="textarea-field font-mono text-sm min-h-[420px]"
                      />
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Controls panel */}
            <div className="order-2 lg:order-1 lg:col-span-4 space-y-4">
              <div className="card">
                <div className="card-header">
                  <div className="flex items-center gap-2">
                    <meta.Icon className="h-5 w-5 text-primary-700" />
                    <h2 className="text-base font-semibold text-slate-900">Scan settings</h2>
                  </div>
                </div>
                <div className="card-body space-y-4">
                  <div>
                    <p className="text-sm font-medium text-slate-700 mb-2">Scanner</p>
                    <div className="flex flex-wrap gap-2">
                      {isScannerEnabled(scannerConfig, 'sql') && (
                        <button
                          onClick={() => setScannerType('sql')}
                          type="button"
                          className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-sm font-medium transition-colors ${
                            scannerType === 'sql'
                              ? 'border-primary-500 bg-primary-50 text-primary-800'
                              : 'border-slate-200 bg-white text-slate-800 hover:bg-slate-50'
                          }`}
                        >
                          <Bug className={`h-4 w-4 ${scannerType === 'sql' ? 'text-primary-700' : 'text-slate-600'}`} />
                          SQL
                        </button>
                      )}
                      {isScannerEnabled(scannerConfig, 'xss') && (
                        <button
                          onClick={() => setScannerType('xss')}
                          type="button"
                          className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-sm font-medium transition-colors ${
                            scannerType === 'xss'
                              ? 'border-primary-500 bg-primary-50 text-primary-800'
                              : 'border-slate-200 bg-white text-slate-800 hover:bg-slate-50'
                          }`}
                        >
                          <Shield className={`h-4 w-4 ${scannerType === 'xss' ? 'text-primary-700' : 'text-slate-600'}`} />
                          XSS
                        </button>
                      )}
                      {isScannerEnabled(scannerConfig, 'command') && (
                        <button
                          onClick={() => setScannerType('command')}
                          type="button"
                          className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-sm font-medium transition-colors ${
                            scannerType === 'command'
                              ? 'border-primary-500 bg-primary-50 text-primary-800'
                              : 'border-slate-200 bg-white text-slate-800 hover:bg-slate-50'
                          }`}
                        >
                          <AlertTriangle className={`h-4 w-4 ${scannerType === 'command' ? 'text-primary-700' : 'text-slate-600'}`} />
                          Command
                        </button>
                      )}
                      {isScannerEnabled(scannerConfig, 'csrf') && (
                        <button
                          onClick={() => setScannerType('csrf')}
                          type="button"
                          className={`inline-flex items-center gap-2 rounded-full border px-3 py-2 text-sm font-medium transition-colors ${
                            scannerType === 'csrf'
                              ? 'border-primary-500 bg-primary-50 text-primary-800'
                              : 'border-slate-200 bg-white text-slate-800 hover:bg-slate-50'
                          }`}
                        >
                          <Shield className={`h-4 w-4 ${scannerType === 'csrf' ? 'text-primary-700' : 'text-slate-600'}`} />
                          CSRF
                        </button>
                      )}
                    </div>
                  </div>

                  <div>
                    <p className="text-sm font-medium text-slate-700 mb-2">Analysis mode</p>
                    <div className="inline-flex rounded-lg shadow-sm overflow-hidden ring-1 ring-slate-200/70" role="group">
                      <button
                        type="button"
                        onClick={() => setAnalysisMode('static')}
                        className={`px-3 py-2 text-sm font-medium ${
                          analysisMode === 'static'
                            ? 'bg-primary-600 text-white'
                            : 'bg-white text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        Static
                      </button>
                      <button
                        type="button"
                        onClick={() => setAnalysisMode('ml')}
                        className={`px-3 py-2 text-sm font-medium border-l border-slate-200/70 ${
                          analysisMode === 'ml'
                            ? 'bg-primary-600 text-white'
                            : 'bg-white text-slate-700 hover:bg-slate-50'
                        }`}
                      >
                        ML
                      </button>
                    </div>
                  </div>

                  <div className="pt-2">
                    <button
                      onClick={handleScan}
                      disabled={!canScan()}
                      className="btn-primary w-full flex items-center justify-center gap-2"
                    >
                      {isScanning ? (
                        <>
                          <Loader2 className="h-5 w-5 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <meta.Icon className="h-5 w-5" />
                          Start scan
                        </>
                      )}
                    </button>
                    {!canScan() && (
                      <p className="mt-2 text-xs text-slate-500">
                        {activeTab === 'url'
                          ? 'Paste a valid URL to enable scanning.'
                          : activeTab === 'file'
                          ? 'Upload a file to enable scanning.'
                          : 'Paste some code to enable scanning.'}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>

      </div>
    </div>
  );
};

export default Scanner; 