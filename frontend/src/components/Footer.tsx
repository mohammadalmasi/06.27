import React from 'react';
import { Shield, Github, MessageCircle } from 'lucide-react';

const Footer: React.FC = () => {
  return (
    <footer className="bg-slate-950 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          {/* Brand Section */}
          <div className="flex flex-col items-center md:items-start">
            <div className="flex items-center space-x-2 mb-4">
              <Shield className="h-8 w-8 text-primary-300" />
              <span className="text-xl font-bold">Vulnerability Scanner</span>
            </div>
            <p className="text-slate-300 text-sm text-center md:text-left">
              Static scanners + optional ML analysis to help identify common web
              vulnerabilities and improve secure development.
            </p>
          </div>

          {/* Links Section */}
          <div className="flex flex-col items-center md:items-start">
            <h3 className="text-lg font-semibold mb-4">Resources</h3>
            <ul className="space-y-2 text-sm text-slate-300">
              <li>
                <a 
                  href="https://github.com/mohammadalmasi/06.27#readme"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-primary-300 transition-colors duration-200"
                >
                  Documentation
                </a>
              </li>
              <li>
                <a 
                  href="https://owasp.org/www-project-top-ten/"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-primary-300 transition-colors duration-200"
                >
                  Security Best Practices
                </a>
              </li>
              <li>
                <a 
                  href="https://cwe.mitre.org/"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-primary-300 transition-colors duration-200"
                >
                  Vulnerability Database
                </a>
              </li>
              <li>
                <a 
                  href="https://github.com/mohammadalmasi/06.27#backend-api-main-endpoints"
                  target="_blank"
                  rel="noreferrer"
                  className="hover:text-primary-300 transition-colors duration-200"
                >
                  API Reference
                </a>
              </li>
            </ul>
          </div>

          {/* Contact Section */}
          <div className="flex flex-col items-center md:items-start">
            <h3 className="text-lg font-semibold mb-4">Connect</h3>
            <div className="flex space-x-4">
              <a 
                href="https://github.com/mohammadalmasi/06.27"
                target="_blank"
                rel="noreferrer"
                className="text-slate-300 hover:text-primary-300 transition-colors duration-200"
                aria-label="GitHub"
              >
                <Github className="h-6 w-6" />
              </a>
              <a 
                href="https://github.com/mohammadalmasi/06.27/issues"
                target="_blank"
                rel="noreferrer"
                className="text-slate-300 hover:text-primary-300 transition-colors duration-200"
                aria-label="Issues"
              >
                <MessageCircle className="h-6 w-6" />
              </a>
            </div>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="border-t border-slate-800/80 mt-8 pt-8 text-center">
          <p className="text-slate-300 text-sm">
            &copy; {new Date().getFullYear()} Vulnerability Scanner. Built for security research and education.
          </p>
          <p className="text-slate-400 text-xs mt-2">
            This tool is designed for educational purposes and authorized security testing only.
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer; 