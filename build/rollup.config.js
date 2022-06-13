import prettier from 'rollup-plugin-prettier';

const prettierConfig = {
    tabWidth: 4,
    singleQuote: true,
    parser: 'babel',
};
const config = {
  input: 'lib/bundle.mjs',
  output: {
    format: 'esm',
    name: 'be8',
    file: './dist/bundle.js',
    preferConst: true,
  },
  plugins: [
    prettier(prettierConfig),
  ]
};

export default config;