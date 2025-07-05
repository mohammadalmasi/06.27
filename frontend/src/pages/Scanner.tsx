import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { 
  Upload, 
  Link as LinkIcon, 
  Code, 
  AlertTriangle, 
  CheckCircle, 
  Loader2,
  FileText,
  X
} from 'lucide-react';
import toast from 'react-hot-toast';

interface ScanInput {
  type: 'url' | 'file' | 'code';
  content: string;
  filename?: string;
}

const Scanner: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'url' | 'file' | 'code'>('url');
  const [isScanning, setIsScanning] = useState(false);
  const [scanInput, setScanInput] = useState<ScanInput>({
    type: 'url',
    content: '',
    filename: ''
  });
  const [uploadedFiles, setUploadedFiles] = useState<File[]>([]);

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
      const formData = new FormData();
      
      if (scanInput.type === 'url') {
        formData.append('url', scanInput.content);
      } else if (scanInput.type === 'file') {
        formData.append('code', scanInput.content);
      } else {
        formData.append('code', scanInput.content);
      }

      // Get JWT token from localStorage
      const token = localStorage.getItem('token');
      const headers: HeadersInit = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const response = await fetch('http://localhost:5001/api/scan', {
        method: 'POST',
        headers,
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Scan failed');
      }

      const results = await response.json();
      
      // Store results in localStorage for the Results page
      localStorage.setItem('scanResults', JSON.stringify(results));
      localStorage.setItem('scanInput', JSON.stringify(scanInput));
      
      toast.success('Scan completed successfully');
      navigate('/results');
      
    } catch (error) {
      console.error('Scan error:', error);
      toast.error('Scan failed. Please try again.');
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

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
            SQL Injection Vulnerability Scanner
          </h1>
          <p className="text-lg text-gray-600">
            Upload your code, paste it directly, or scan GitHub files for SQL injection vulnerabilities
          </p>
        </div>

        {/* Main Scanner Interface */}
        <div className="bg-white rounded-lg shadow-lg overflow-hidden">
          {/* Tab Navigation */}
          <div className="flex border-b border-gray-200">
            <button
              onClick={() => handleTabChange('url')}
              className={`flex-1 py-4 px-6 text-center font-medium transition-colors duration-200 ${
                activeTab === 'url'
                  ? 'bg-primary-50 text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <LinkIcon className="h-5 w-5 mx-auto mb-1" />
              GitHub URL
            </button>
            <button
              onClick={() => handleTabChange('file')}
              className={`flex-1 py-4 px-6 text-center font-medium transition-colors duration-200 ${
                activeTab === 'file'
                  ? 'bg-primary-50 text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <Upload className="h-5 w-5 mx-auto mb-1" />
              File Upload
            </button>
            <button
              onClick={() => handleTabChange('code')}
              className={`flex-1 py-4 px-6 text-center font-medium transition-colors duration-200 ${
                activeTab === 'code'
                  ? 'bg-primary-50 text-primary-600 border-b-2 border-primary-600'
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
              }`}
            >
              <Code className="h-5 w-5 mx-auto mb-1" />
              Paste Code
            </button>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {/* URL Tab */}
            {activeTab === 'url' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    GitHub Python File URL
                  </label>
                  <input
                    type="url"
                    value={scanInput.content}
                    onChange={(e) => handleInputChange(e.target.value)}
                    placeholder="https://github.com/user/repo/blob/main/file.py"
                    className="input-field"
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    Enter a direct link to a Python file on GitHub
                  </p>
                </div>
              </div>
            )}

            {/* File Upload Tab */}
            {activeTab === 'file' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Upload Source Code File
                  </label>
                  
                  {uploadedFiles.length === 0 ? (
                    <div
                      {...getRootProps()}
                      className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors duration-200 ${
                        isDragActive
                          ? 'border-primary-400 bg-primary-50'
                          : 'border-gray-300 hover:border-gray-400'
                      }`}
                    >
                      <input {...getInputProps()} />
                      <Upload className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                      <p className="text-lg font-medium text-gray-700 mb-2">
                        {isDragActive
                          ? 'Drop your file here'
                          : 'Drag and drop your file here, or click to browse'}
                      </p>
                      <p className="text-sm text-gray-500">
                        Supports .py, .js, .php, .java, .cs, .ts files (max 2MB)
                      </p>
                    </div>
                  ) : (
                    <div className="border border-gray-300 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <FileText className="h-8 w-8 text-primary-600" />
                          <div>
                            <p className="font-medium text-gray-900">
                              {uploadedFiles[0].name}
                            </p>
                            <p className="text-sm text-gray-500">
                              {(uploadedFiles[0].size / 1024).toFixed(1)} KB
                            </p>
                          </div>
                        </div>
                        <button
                          onClick={removeFile}
                          className="text-gray-400 hover:text-gray-600"
                        >
                          <X className="h-5 w-5" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Code Paste Tab */}
            {activeTab === 'code' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Paste Source Code
                  </label>
                  <textarea
                    value={scanInput.content}
                    onChange={(e) => handleInputChange(e.target.value)}
                    placeholder="# Paste your Python code here..."
                    rows={12}
                    className="textarea-field font-mono text-sm"
                  />
                  <p className="text-sm text-gray-500 mt-1">
                    Paste your source code directly for analysis
                  </p>
                </div>
              </div>
            )}

            {/* Scan Button */}
            <div className="mt-6 pt-6 border-t border-gray-200">
              <button
                onClick={handleScan}
                disabled={!canScan()}
                className={`w-full py-3 px-4 rounded-lg font-medium transition-colors duration-200 flex items-center justify-center ${
                  canScan()
                    ? 'bg-primary-600 hover:bg-primary-700 text-white'
                    : 'bg-gray-200 text-gray-500 cursor-not-allowed'
                }`}
              >
                {isScanning ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin mr-2" />
                    Scanning Code...
                  </>
                ) : (
                  <>
                    <CheckCircle className="h-5 w-5 mr-2" />
                    Start Security Scan
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Information Cards */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">
              Supported Languages
            </h3>
            <ul className="space-y-2 text-sm text-gray-600">
              <li className="flex items-center">
                <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                Python (.py)
              </li>
            </ul>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">
              Detection Capabilities
            </h3>
            <ul className="space-y-2 text-sm text-gray-600">
              <li className="flex items-center">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mr-2" />
                String concatenation vulnerabilities
              </li>
              <li className="flex items-center">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mr-2" />
                Dynamic query construction
              </li>
              <li className="flex items-center">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mr-2" />
                Parameterized query validation
              </li>
              <li className="flex items-center">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mr-2" />
                NoSQL injection patterns
              </li>
              <li className="flex items-center">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mr-2" />
                Framework-specific vulnerabilities
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Scanner; 