import prettier from 'rollup-plugin-prettier';
import eslint from '@rollup/plugin-eslint';

const prettierConfig = {
    tabWidth: 4,
    singleQuote: true,
    parser: 'babel',
};
const eslintConfig = {
    fix: true,
    requireConfigFile: false,
    include: ['lib/*.mjs'],
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
    eslint(eslintConfig),
    prettier(prettierConfig)
  ]
};

export default config;