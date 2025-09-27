const path = require('path');

module.exports = {
  entry: {
    'auth-handler': './src/handlers/auth-handler.ts',
    'user-handler': './src/handlers/user-handler.ts',
    'profile-handler': './src/handlers/profile-handler.ts',
  },
  target: 'node',
  mode: 'production',
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  output: {
    filename: '[name].js',
    path: path.resolve(__dirname, 'dist'),
    libraryTarget: 'commonjs2',
  },
  externals: {
    'aws-sdk': 'aws-sdk',
    'sequelize': 'sequelize',
    'pg': 'pg',
    'pg-hstore': 'pg-hstore',
    'bcryptjs': 'bcryptjs',
    'jsonwebtoken': 'jsonwebtoken',
    'joi': 'joi',
    'uuid': 'uuid',
  },
  optimization: {
    minimize: false,
  },
};
