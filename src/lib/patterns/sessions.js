// Session Management vulnerability patterns

import { patternCategories } from './categories.js';

export const sessionPatterns = {
  sessionFixation: {
    // Session identifiers set from user-controlled data
    pattern: /req\.sessionID?\s*=\s*req\.(?:query|body)\./i,
    description: 'Potential session fixation vulnerability',
    severity: 'HIGH',
    category: patternCategories.SESSION_MANAGEMENT,
    subcategory: '384',
    cwe: '384'
  }
};

export default sessionPatterns;