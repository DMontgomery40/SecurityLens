import React from 'react';
import { 
  AlertTriangle, 
  Shield, 
  Info, 
  AlertCircle, 
  RefreshCw, 
  Clock, 
  ExternalLink, 
  Book
} from 'lucide-react';

// Reusable components with enhanced styling
const Card = ({ children, className = '', highlight = false }) => (
  <div className={`
    bg-white rounded-xl shadow-sm border border-gray-100
    transition-all duration-200 ease-in-out relative
    before:absolute before:inset-0 before:rounded-xl before:bg-gradient-to-b 
    before:from-white before:to-gray-50 before:opacity-0 before:transition-opacity
    hover:before:opacity-100
    ${highlight ? 'hover:shadow-lg hover:border-blue-100 hover:scale-[1.01]' : ''}
    ${className}
  `}>
    <div className="relative">{children}</div>
  </div>
);

const Alert = ({ children, variant = 'info', className = '' }) => {
  const variants = {
    info: 'bg-blue-50/40 ring-blue-200 text-blue-800 shadow-blue-100/50',
    error: 'bg-red-50/40 ring-red-200 text-red-800 shadow-red-100/50',
    warning: 'bg-yellow-50/40 ring-yellow-200 text-yellow-800 shadow-yellow-100/50',
    success: 'bg-green-50/40 ring-green-200 text-green-800 shadow-green-100/50'
  };

  return (
    <div className={`
      flex items-start p-4 rounded-lg 
      ring-1 ring-inset ring-opacity-50
      backdrop-blur-sm backdrop-filter
      shadow-sm
      transition-all duration-200
      hover:ring-opacity-100 hover:bg-opacity-100
      ${variants[variant]} ${className}
    `}>
      <div className="relative w-full">
        {children}
      </div>
    </div>
  );
};

const Badge = ({ children, variant = 'default', className = '' }) => {
  const variants = {
    default: 'bg-gray-100/80 text-gray-800 hover:bg-gray-200/90 ring-gray-200',
    danger: 'bg-red-50/80 text-red-800 hover:bg-red-100/90 ring-red-200',
    warning: 'bg-yellow-50/80 text-yellow-800 hover:bg-yellow-100/90 ring-yellow-200',
    success: 'bg-green-50/80 text-green-800 hover:bg-green-100/90 ring-green-200',
    info: 'bg-blue-50/80 text-blue-800 hover:bg-blue-100/90 ring-blue-200'
  };

  return (
    <span className={`
      inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium
      transition-all duration-150 ease-out
      ring-1 ring-inset ring-opacity-50
      backdrop-blur-sm backdrop-filter
      hover:ring-opacity-100
      ${variants[variant]} ${className}
    `}>
      {children}
    </span>
  );
};

const TimeToReset = ({ resetTimestamp }) => {
  const [timeLeft, setTimeLeft] = React.useState('');

  React.useEffect(() => {
    const updateTime = () => {
      const now = new Date().getTime();
      const reset = new Date(resetTimestamp * 1000).getTime();
      const diff = reset - now;

      if (diff <= 0) {
        setTimeLeft('Reset now');
        return;
      }

      const minutes = Math.floor(diff / 60000);
      const seconds = Math.floor((diff % 60000) / 1000);
      setTimeLeft(`${minutes}m ${seconds}s`);
    };

    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, [resetTimestamp]);

  return (
    <div className="flex items-center text-sm font-medium text-gray-500">
      <Clock className="h-4 w-4 mr-1.5 text-gray-400" />
      {timeLeft}
    </div>
  );
};

const CodeBlock = ({ children }) => (
  <div className="group relative overflow-hidden">
    <div className="absolute inset-0 rounded bg-gradient-to-r from-gray-900/[0.03] to-gray-900/[0.06] opacity-50 group-hover:opacity-100 transition-opacity duration-150" />
    <div className="absolute inset-0 bg-gradient-to-r from-blue-500/[0.03] to-blue-500/[0.06] opacity-0 group-hover:opacity-100 transition-opacity duration-150" />
    <div className="absolute right-0 h-full w-1 bg-blue-500/10 transform translate-x-full group-hover:translate-x-0 transition-transform duration-150" />
    <code className="relative block font-mono text-sm px-4 py-3 rounded bg-transparent">
      {children}
    </code>
  </div>
);

const ScanResults = ({ results, usedCache, onRefreshRequest, scanning }) => {
  if (!results) return null;

  const { summary, findings, recommendedFixes, rateLimit } = results;

  // Safety checks
  if (!findings || typeof findings !== 'object') {
    console.error('Invalid findings structure');
    return (
      <Alert variant="error">
        <AlertTriangle className="h-5 w-5 mr-2 flex-shrink-0" />
        <span>Invalid scan results structure. Please try again.</span>
      </Alert>
    );
  }

  const safeRecommendedFixes = recommendedFixes && Array.isArray(recommendedFixes) 
    ? recommendedFixes 
    : [];

  const severityConfig = {
    CRITICAL: {
      icon: AlertTriangle,
      color: 'text-red-500',
      bg: 'bg-red-50',
      border: 'border-red-100',
      badge: 'danger'
    },
    HIGH: {
      icon: AlertCircle,
      color: 'text-orange-500',
      bg: 'bg-orange-50',
      border: 'border-orange-100',
      badge: 'warning'
    },
    MEDIUM: {
      icon: AlertCircle,
      color: 'text-yellow-500',
      bg: 'bg-yellow-50',
      border: 'border-yellow-100',
      badge: 'warning'
    },
    LOW: {
      icon: Info,
      color: 'text-blue-500',
      bg: 'bg-blue-50',
      border: 'border-blue-100',
      badge: 'info'
    }
  };

  // Helper function to consolidate findings by type
  const consolidateFindings = (findings) => {
    if (!findings || typeof findings !== 'object') return {};
    
    const consolidated = {};
    
    try {
      Object.entries(findings).forEach(([category, subcategories]) => {
        if (!subcategories || typeof subcategories !== 'object') return;
        
        Object.entries(subcategories).forEach(([subcategory, issues]) => {
          if (!Array.isArray(issues)) return;
          
          issues.forEach(issue => {
            if (!issue || !issue.type) return;
            
            const key = issue.type;
            if (!consolidated[key]) {
              consolidated[key] = {
                ...issue,
                files: [],
                allLineNumbers: {}
              };
            }
            consolidated[key].files.push(issue.file);
            consolidated[key].allLineNumbers[issue.file] = issue.lineNumbers;
          });
        });
      });
    } catch (error) {
      console.error('Error consolidating findings:', error);
    }
    
    return consolidated;
  };

  return (
    <div className="space-y-8">
      {/* Status Bar */}
      {rateLimit && (
        <Card className="bg-gray-50/50 backdrop-blur-sm">
          <div className="flex items-center justify-between p-4">
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2">
                <Info className="h-4 w-4 text-gray-400" />
                <span className="text-sm font-medium text-gray-600">
                  API Calls: {rateLimit.remaining}/{rateLimit.limit}
                </span>
              </div>
              <TimeToReset resetTimestamp={rateLimit.reset} />
            </div>
            {usedCache && !scanning && (
              <button
                onClick={onRefreshRequest}
                disabled={rateLimit.remaining === 0}
                className="
                  flex items-center px-3 py-1.5 text-sm font-medium
                  text-blue-600 hover:text-blue-700
                  disabled:opacity-50 disabled:cursor-not-allowed
                  transition-colors duration-150
                "
              >
                <RefreshCw className={`h-4 w-4 mr-1.5 ${scanning ? 'animate-spin' : ''}`} />
                Refresh Scan
              </button>
            )}
          </div>
        </Card>
      )}

      {/* Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity, index) => {
          const count = summary[`${severity.toLowerCase()}Issues`] || 0;
          const config = severityConfig[severity];
          const Icon = config.icon;
          
          return (
            <Card 
              key={severity}
              highlight
              className={`
                ${config.bg} border-0 overflow-hidden
                transform transition-all duration-300 ease-out
                hover:scale-[1.02]
                hover:shadow-lg hover:shadow-${severity.toLowerCase() === 'critical' ? 'red' : 
                                            severity.toLowerCase() === 'high' ? 'orange' : 
                                            severity.toLowerCase() === 'medium' ? 'yellow' : 
                                            'blue'}-100/50
                motion-safe:animate-fade-in
                motion-safe:animate-delay-${index * 100}
              `}
            >
              <div className="p-6 relative">
                <div className="absolute top-0 right-0 mt-4 mr-4 transform transition-transform duration-200 group-hover:scale-110">
                  <Icon className={`h-5 w-5 ${config.color}`} />
                </div>
                <div className="space-y-2">
                  <div className="text-3xl font-bold tracking-tight">
                    {count}
                  </div>
                  <div className="text-sm font-medium text-gray-800">
                    {severity} {count === 1 ? 'Issue' : 'Issues'}
                  </div>
                </div>
                <div className="absolute bottom-0 right-0 w-32 h-32 -mr-8 -mb-8 bg-current opacity-[0.03] rounded-full blur-2xl transition-opacity duration-500 ease-in-out group-hover:opacity-[0.06]" />
              </div>
            </Card>
          );
        })}
      </div>

      {/* Consolidated Findings */}
      <div className="space-y-6">
        {Object.entries(consolidateFindings(findings)).map(([type, finding]) => {
          const config = severityConfig[finding.severity];
          const Icon = config.icon;

          return (
            <Card key={type} className="overflow-hidden">
              <div className="p-6">
                <div className="flex items-start space-x-4">
                  <div className={`${config.bg} p-2 rounded-lg`}>
                    <Icon className={`h-5 w-5 ${config.color}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <h3 className="text-lg font-semibold text-gray-900">
                        {type}
                      </h3>
                      {finding.subcategory && (
                        <Badge variant={config.badge}>
                          CWE-{finding.subcategory}
                        </Badge>
                      )}
                    </div>
                    <p className="mt-1 text-gray-600">
                      {finding.description}
                    </p>

                    {/* Affected Files */}
                    {Object.entries(finding.allLineNumbers).length > 0 && (
                      <div className="mt-4 space-y-3">
                        <div className="flex items-center space-x-2 text-sm text-gray-500">
                          <Info className="h-4 w-4" />
                          <span>Affected Files</span>
                        </div>
                        {Object.entries(finding.allLineNumbers).map(([file, lines]) => (
                          <div key={file} className="group">
                            <CodeBlock>
                              <div className="flex items-start justify-between">
                                <div className="font-mono">
                                  {file}
                                </div>
                                {lines?.length > 0 && (
                                  <div className="text-gray-500 text-sm">
                                    Line{lines.length > 1 ? 's' : ''}: {lines.join(', ')}
                                  </div>
                                )}
                              </div>
                            </CodeBlock>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Recommendation */}
                    {finding.recommendation && (
                      <Alert className="mt-4">
                        <Info className="h-4 w-4 mr-2 flex-shrink-0" />
                        <span>{finding.recommendation}</span>
                      </Alert>
                    )}
                  </div>
                </div>
              </div>
            </Card>
          );
        })}
      </div>

      {/* Security References Section */}
      {safeRecommendedFixes.length > 0 && (
        <Card className="divide-y divide-gray-100">
          <div className="p-6">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-50 rounded-lg">
                <Shield className="h-5 w-5 text-blue-500" />
              </div>
              <h2 className="text-xl font-semibold text-gray-900">
                Security References & Mitigation
              </h2>
            </div>
          </div>

          <div className="divide-y divide-gray-100">
            {Array.from(new Set(safeRecommendedFixes.map(fix => fix.type))).map(type => {
              const fix = safeRecommendedFixes.find(f => f.type === type);
              return (
                <div key={type} className="p-6">
                  <div className="space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <h3 className="text-lg font-semibold text-gray-900">
                            {type}
                          </h3>
                          {fix.cwe && (
                            <a 
                              href={`https://cwe.mitre.org/data/definitions/${fix.cwe}.html`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="group"
                            >
                              <Badge className="hover:bg-blue-100 transition-colors duration-150">
                                <span className="flex items-center space-x-1">
                                  <span>CWE-{fix.cwe}</span>
                                  <ExternalLink className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                                </span>
                              </Badge>
                            </a>
                          )}
                        </div>
                        <p className="text-gray-600 leading-relaxed">
                          {fix.recommendation}
                        </p>
                      </div>
                    </div>

                    {fix.references?.length > 0 && (
                      <div className="pt-4">
                        <div className="flex items-center space-x-2 mb-4 text-sm font-medium text-gray-900">
                          <Book className="h-4 w-4 text-blue-500" />
                          <span>Additional Resources</span>
                        </div>
                        <div className="grid gap-3">
                          {fix.references.map((ref, i) => (
                            <a
                              key={i}
                              href={ref.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="group block"
                            >
                              <Card highlight className="p-4">
                                <div className="flex items-start justify-between">
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center space-x-2">
                                      <Book className="h-4 w-4 text-blue-500" />
                                      <h5 className="font-medium text-blue-600 group-hover:text-blue-800">
                                        {ref.title}
                                      </h5>
                                      <ExternalLink className="h-3 w-3 text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                                    </div>
                                    {ref.description && (
                                      <p className="mt-1 text-sm text-gray-600 overflow-hidden">
                                        {ref.description}
                                      </p>
                                    )}
                                  </div>
                                </div>
                              </Card>
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Cache Notice */}
      {usedCache && (
        <Alert className="mt-4">
          <div className="flex items-center justify-between w-full">
            <div className="flex items-center">
              <Info className="h-4 w-4 mr-2 flex-shrink-0 text-blue-500" />
              <span>Results are from cached data</span>
            </div>
            {!scanning && (
              <button
                onClick={onRefreshRequest}
                className="
                  ml-4 px-3 py-1 text-sm font-medium text-blue-600 
                  hover:text-blue-700 disabled:opacity-50 
                  disabled:cursor-not-allowed transition-colors
                "
                disabled={rateLimit?.remaining === 0}
              >
                Perform fresh scan
              </button>
            )}
          </div>
        </Alert>
      )}
    </div>
  );
};

export default ScanResults;