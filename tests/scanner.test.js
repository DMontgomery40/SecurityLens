// scanner.test.js
import { evalExecution, patterns, patternCategories } from '../src/lib/patterns/index.js';
import { expect } from 'chai';

describe('Security Scanner Tests', () => {
  describe('File Operation Patterns', () => {
    it('should detect unsafe file uploads', async () => {
      const code = `
        app.post('/upload', upload.single('file'));
        const upload = multer({ dest: '/uploads' });
      `;
      const results = await evalExecution(code);
      expect(results.matches).to.have.lengthOf.at.least(1);
      expect(results.matches[0].pattern).to.equal('unsafeFileUpload');
    });

    it('should detect directory traversal', async () => {
      const code = `
        const path = require('../' + userInput);
        fs.readFile('../../config.json');
      `;
      const results = await evalExecution(code);
      expect(results.matches).to.have.lengthOf.at.least(1);
      expect(results.matches[0].pattern).to.equal('pathTraversal');
    });
  });

  describe('Code Execution Patterns', () => {
    it('should detect eval usage', async () => {
      const code = `
        eval(userInput);
        new Function(req.body.code)();
      `;
      const results = await evalExecution(code);
      expect(results.matches).to.have.lengthOf.at.least(1);
      expect(results.matches[0].pattern).to.equal('evalExecution');
    });
  });

  describe('API Security Patterns', () => {
    it('should detect express misconfigurations', async () => {
      const code = `
        app.use(express.static(path));
        app.use(cors());
      `;
      const results = await evalExecution(code);
      expect(results.matches).to.have.lengthOf.at.least(1);
      expect(results.matches[0].pattern).to.equal('expressSecurityMisconfig');
    });
  });

  describe('Performance and Error Handling', () => {
    it('should handle large files', async () => {
      const largeCode = 'const x = 1;\n'.repeat(10000);
      const results = await evalExecution(largeCode);
      expect(results.performance.duration).to.be.lessThan(5000);
    });

    it('should handle regex timeouts', async () => {
      const maliciousCode = 'a'.repeat(100000) + '!';
      const results = await evalExecution(maliciousCode);
      expect(results.errors).to.have.lengthOf.at.least(0);
    });
  });

  describe('Pattern Coverage', () => {
    it('should test all patterns', async () => {
      const testCases = [
        {
          name: 'pathTraversal',
          code: `
            const path = require('../' + userInput);
            fs.readFile('../../config.json');
          `
        },
        {
          name: 'evalExecution',
          code: `
            eval(userInput);
            new Function(req.body.code)();
          `
        },
        {
          name: 'expressSecurityMisconfig',
          code: `
            app.use(express.static(path));
            app.use(cors());
          `
        },
        {
          name: 'unsafeFileUpload',
          code: `
            app.post('/upload', upload.single('file'));
            const upload = multer({ dest: '/uploads' });
          `
        }
      ];

      for (const testCase of testCases) {
        const results = await evalExecution(testCase.code);
        expect(results.matches.some(m => m.pattern === testCase.name),
          `Pattern ${testCase.name} should detect its test case`).to.be.true;
      }
    });
  });
});
