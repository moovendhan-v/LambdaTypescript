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

const environment = process.env.NODE_ENV || 'development';
const dbConfig = config[environment];

let sequelizeInstance: Sequelize;

export const getSequelizeInstance = (): Sequelize => {
  if (!sequelizeInstance) {
    sequelizeInstance = new Sequelize(dbConfig);
  }
  return sequelizeInstance;
};

export const sequelize = getSequelizeInstance();

export { config };