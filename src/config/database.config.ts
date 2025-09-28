// src/config/database.config.ts
import { Sequelize, Options as SequelizeOptions } from 'sequelize';
import { logger } from '@/utils/logger';

interface DatabaseConfig {
  [key: string]: SequelizeOptions;
}

const config: DatabaseConfig = {
  development: {
    host: 'localhost',
    port: 5432,
    database: 'lambda_dev',
    username: 'postgres',
    password: 'postgres',
    dialect: 'postgres',
    logging: (msg: string) => logger.debug(msg),
  },
  test: {
    host: 'localhost',
    port: 5433,
    database: 'lambda_test',
    username: 'postgres',
    password: 'postgres',
    dialect: 'postgres',
    logging: false,
  },
  production: {
    host: process.env.DB_HOST!,
    port: parseInt(process.env.DB_PORT || '5432'),
    database: process.env.DB_NAME!,
    username: process.env.DB_USER!,
    password: process.env.DB_PASSWORD!,
    dialect: 'postgres',
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
    },
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
  },
};

const environment = process.env.ENVIRONMENT === 'dev' ? 'development' :
                   process.env.ENVIRONMENT === 'staging' ? 'test' :
                   process.env.ENVIRONMENT === 'prod' ? 'production' :
                   process.env.NODE_ENV || 'development';

logger.info('Database config environment variables:', {
  ENVIRONMENT: process.env.ENVIRONMENT,
  DATABASE_HOST: process.env.DATABASE_HOST,
  DATABASE_PORT: process.env.DATABASE_PORT,
  DATABASE_NAME: process.env.DATABASE_NAME,
  DATABASE_USER: process.env.DATABASE_USER,
  NODE_ENV: process.env.NODE_ENV,
});

// Override config with environment variables if available
const dbConfig = {
  ...config[environment],
  host: process.env.DATABASE_HOST || config[environment].host,
  port: parseInt(process.env.DATABASE_PORT || config[environment].port?.toString() || '5432'),
  database: process.env.DATABASE_NAME || config[environment].database,
  username: process.env.DATABASE_USER || config[environment].username,
  password: process.env.DATABASE_PASSWORD || config[environment].password,
  dialect: config[environment].dialect,
};

logger.info('Final database config:', {
  environment,
  host: dbConfig.host,
  port: dbConfig.port,
  database: dbConfig.database,
  username: dbConfig.username,
});

let sequelizeInstance: Sequelize;

export const getSequelizeInstance = (): Sequelize => {
  if (!sequelizeInstance) {
    sequelizeInstance = new Sequelize(dbConfig);
  }
  return sequelizeInstance;
};

export const sequelize = getSequelizeInstance();

export { config };