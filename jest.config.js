export default {
  transform: {
    '^.+\\.[t|j]sx?$': 'babel-jest'
  },
  extensionsToTreatAsEsm: ['.jsx'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  testEnvironment: 'node',
  transformIgnorePatterns: [
    'node_modules/(?!(@babel|lodash-es|chai)/)'
  ]
};
