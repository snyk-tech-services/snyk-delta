module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  collectCoverageFrom: ['lib/**/*.ts'],
  coverageReporters: ['text-summary', 'html'],
  verbose: true,
  transform: {
    '^.+\\.[t|j]sx?$': 'babel-jest',
  },
  // Add a custom pattern to transform specific node_modules
  transformIgnorePatterns: [
    '/node_modules/(?!axios)/', // Tell Jest to transform 'axios' and its dependencies
  ],
};
