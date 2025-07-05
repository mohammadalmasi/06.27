import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  Download, 
  ArrowLeft,
  FileText,
  Code,
  Shield,
  AlertCircle,
  Eye,
  EyeOff
} from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface Vulnerability {
  file_path: string;
  line_number: number;
  vulnerability_type: string;
  description: string;
  severity: string;
  code_snippet: string;
  remediation: string;
  confidence: number;
}

interface ScanResults {
  vulnerabilities: Vulnerability[];
  summary: {
    total_vulnerabilities: number;
    high_severity: number;
    medium_severity: number;
    low_severity: number;
  };
  scan_timestamp: string;
  file_name?: string;
  highlighted_code?: string;
  original_code?: string;
}

const Results: React.FC = () => {
  const navigate = useNavigate();
  const [results, setResults] = useState<ScanResults | null>(null);
  const [scanInput, setScanInput] = useState<any>(null);
  const [expandedVulnerabilities, setExpandedVulnerabilities] = useState<Set<number>>(new Set());
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  useEffect(() => {
    const storedResults = localStorage.getItem('scanResults');
    const storedInput = localStorage.getItem('scanInput');
    
    if (storedResults) {
      setResults(JSON.parse(storedResults));
    }
    
    if (storedInput) {
      setScanInput(JSON.parse(storedInput));
    }
    
    // If no results found, redirect to scanner
    if (!storedResults) {
      navigate('/scanner');
    }
  }, [navigate]);

  const toggleVulnerability = (index: number) => {
    const newExpanded = new Set(expandedVulnerabilities);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedVulnerabilities(newExpanded);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'text-danger-600 bg-danger-50 border-danger-200';
      case 'medium':
        return 'text-warning-600 bg-warning-50 border-warning-200';
      case 'low':
        return 'text-success-600 bg-success-50 border-success-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-danger-600" />;
      case 'medium':
        return <AlertCircle className="h-5 w-5 text-warning-600" />;
      case 'low':
        return <Info className="h-5 w-5 text-success-600" />;
      default:
        return <Info className="h-5 w-5 text-gray-600" />;
    }
  };

  const filteredVulnerabilities = results?.vulnerabilities.filter(vuln => {
    if (filterSeverity === 'all') return true;
    return vuln.severity.toLowerCase() === filterSeverity.toLowerCase();
  }) || [];

  const downloadReport = () => {
    if (!results) return;
    
    const reportData = {
      scan_timestamp: new Date().toISOString(),
      input_type: scanInput?.type || 'unknown',
      file_name: scanInput?.filename || 'N/A',
      summary: results.summary,
      vulnerabilities: results.vulnerabilities
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-scan-report-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (!results) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="loading-spinner mx-auto mb-4"></div>
          <p className="text-gray-600">Loading scan results...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Link
                to="/scanner"
                className="flex items-center text-primary-600 hover:text-primary-700 transition-colors duration-200"
              >
                <ArrowLeft className="h-5 w-5 mr-2" />
                Back to Scanner
              </Link>
              <div className="h-6 w-px bg-gray-300"></div>
              <h1 className="text-2xl md:text-3xl font-bold text-gray-900">
                Security Scan Results
              </h1>
            </div>
            
            <button
              onClick={downloadReport}
              className="btn-primary flex items-center"
            >
              <Download className="h-4 w-4 mr-2" />
              Download Report
            </button>
          </div>
          
          <div className="mt-4 text-sm text-gray-600">
            <p>
              <strong>Source:</strong> {scanInput?.filename || scanInput?.type || 'N/A'} •
              <strong className="ml-2">Scanned:</strong> {new Date().toLocaleString()}
            </p>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-primary-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Total Issues</p>
                <p className="text-2xl font-bold text-gray-900">
                  {results.summary.total_vulnerabilities}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <AlertTriangle className="h-8 w-8 text-danger-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">High Severity</p>
                <p className="text-2xl font-bold text-danger-600">
                  {results.summary.high_severity}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <AlertCircle className="h-8 w-8 text-warning-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Medium Severity</p>
                <p className="text-2xl font-bold text-warning-600">
                  {results.summary.medium_severity}
                </p>
              </div>
            </div>
          </div>
          
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <Info className="h-8 w-8 text-success-600 mr-3" />
              <div>
                <p className="text-sm font-medium text-gray-600">Low Severity</p>
                <p className="text-2xl font-bold text-success-600">
                  {results.summary.low_severity}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <div className="flex flex-wrap items-center gap-4">
            <h3 className="text-lg font-semibold text-gray-900">Filter by Severity:</h3>
            <div className="flex space-x-2">
              {['all', 'high', 'medium', 'low'].map((severity) => (
                <button
                  key={severity}
                  onClick={() => setFilterSeverity(severity)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                    filterSeverity === severity
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  {severity.charAt(0).toUpperCase() + severity.slice(1)}
                  {severity !== 'all' && (
                    <span className="ml-1 text-xs">
                      ({results.summary[`${severity}_severity` as keyof typeof results.summary]})
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Highlighted Source Code */}
        {results.highlighted_code && (
          <div className="bg-white rounded-lg shadow mb-8">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <Code className="h-5 w-5 mr-2" />
                Source Code Analysis
              </h3>
              <p className="text-sm text-gray-600 mt-1">
                Vulnerable code sections are highlighted in red. Hover over highlighted areas for vulnerability details.
              </p>
            </div>
            <div className="p-6">
              <div className="rounded-lg overflow-hidden border border-gray-300 shadow-inner">
                {/* Code Editor Header */}
                <div className="bg-gray-800 px-4 py-3 flex items-center justify-between border-b border-gray-700">
                  <div className="flex items-center space-x-3">
                    <FileText className="h-4 w-4 text-gray-300" />
                    <span className="text-gray-200 text-sm font-medium">
                      {scanInput?.filename || 'scanned_code.py'}
                    </span>
                    <span className="text-xs text-gray-400 bg-gray-700 px-2 py-1 rounded">
                      Python
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="flex space-x-1">
                      <div className="w-3 h-3 rounded-full bg-red-500"></div>
                      <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                      <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    </div>
                  </div>
                </div>
                
                {/* Code Content */}
                <div className="bg-gray-900">
                  <div className="flex">
                    {/* Line Numbers */}
                    <div className="bg-gray-800 px-3 py-4 text-right text-gray-400 text-sm font-mono border-r border-gray-700 select-none">
                      {results.original_code?.split('\n').map((_, index) => (
                        <div key={index} className="leading-6">
                          {index + 1}
                        </div>
                      ))}
                    </div>
                    
                    {/* Code with Highlighting */}
                    <div className="flex-1 overflow-x-auto">
                      <pre 
                        className="text-sm text-gray-100 font-mono leading-6 code-content p-4"
                        dangerouslySetInnerHTML={{ __html: results.highlighted_code }}
                        style={{
                          whiteSpace: 'pre',
                          margin: 0,
                          padding: '1rem',
                          textAlign: 'left',
                          fontFamily: '"Fira Code", Monaco, "Cascadia Code", "Roboto Mono", monospace',
                          tabSize: 2,
                          overflowWrap: 'normal'
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Vulnerabilities List */}
        <div className="space-y-6">
          {filteredVulnerabilities.length === 0 ? (
            <div className="bg-white rounded-lg shadow p-8 text-center">
              <CheckCircle className="h-16 w-16 text-success-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                {filterSeverity === 'all' ? 'No Vulnerabilities Found' : `No ${filterSeverity} Severity Issues`}
              </h3>
              <p className="text-gray-600">
                {filterSeverity === 'all' 
                  ? 'Great! Your code appears to be secure from SQL injection vulnerabilities.'
                  : `There are no ${filterSeverity} severity vulnerabilities in your code.`
                }
              </p>
            </div>
          ) : (
            filteredVulnerabilities.map((vulnerability, index) => (
              <div key={index} className="bg-white rounded-lg shadow overflow-hidden">
                <div 
                  className={`p-6 border-l-4 cursor-pointer hover:bg-gray-50 transition-colors duration-200 ${getSeverityColor(vulnerability.severity).replace('bg-', 'border-').replace('-50', '-500')}`}
                  onClick={() => toggleVulnerability(index)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      {getSeverityIcon(vulnerability.severity)}
                      <div className="flex-1">
                        <h3 className="text-lg font-semibold text-gray-900 mb-1">
                          {vulnerability.vulnerability_type.replace(/_/g, ' ')}
                        </h3>
                        <p className="text-gray-600 mb-2">{vulnerability.description}</p>
                        <div className="flex items-center space-x-4 text-sm text-gray-500">
                          <span className="flex items-center">
                            <FileText className="h-4 w-4 mr-1" />
                            Line {vulnerability.line_number}
                          </span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(vulnerability.severity)}`}>
                            {vulnerability.severity.toUpperCase()}
                          </span>
                          <span>
                            Confidence: {Math.round(vulnerability.confidence * 100)}%
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center text-gray-400">
                      {expandedVulnerabilities.has(index) ? (
                        <EyeOff className="h-5 w-5" />
                      ) : (
                        <Eye className="h-5 w-5" />
                      )}
                    </div>
                  </div>
                </div>

                {expandedVulnerabilities.has(index) && (
                  <div className="border-t border-gray-200 bg-gray-50 p-6">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      {/* Code Snippet */}
                      <div>
                        <h4 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                          <Code className="h-4 w-4 mr-2" />
                          Vulnerable Code
                        </h4>
                        <div className="rounded-lg overflow-hidden">
                          <SyntaxHighlighter
                            language="python"
                            style={vscDarkPlus}
                            className="text-sm"
                            showLineNumbers={true}
                            startingLineNumber={Math.max(1, vulnerability.line_number - 2)}
                          >
                            {vulnerability.code_snippet}
                          </SyntaxHighlighter>
                        </div>
                      </div>

                      {/* Remediation */}
                      <div>
                        <h4 className="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                          <Shield className="h-4 w-4 mr-2" />
                          Remediation
                        </h4>
                        <div className="bg-white rounded-lg p-4 border border-gray-200">
                          <p className="text-sm text-gray-700 leading-relaxed">
                            {vulnerability.remediation}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* Bottom Actions */}
        <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            to="/scanner"
            className="btn-primary flex items-center justify-center"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Scan Another File
          </Link>
          
          <button
            onClick={downloadReport}
            className="btn-secondary flex items-center justify-center"
          >
            <Download className="h-4 w-4 mr-2" />
            Download Full Report
          </button>
        </div>
      </div>
    </div>
  );
};

export default Results; 