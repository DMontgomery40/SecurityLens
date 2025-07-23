// DEPRECATED: This file is maintained for backward compatibility only
// Please import from './patterns/index.js' instead

// Re-export everything from the new modular structure
export { patterns, patternCategories, recommendations, categoryMetadata } from './patterns/index.js';

// Default export for backward compatibility
import patterns from './patterns/index.js';
export default patterns;

console.warn('DEPRECATED: Importing from patterns.js is deprecated. Please update to import from patterns/index.js instead.');