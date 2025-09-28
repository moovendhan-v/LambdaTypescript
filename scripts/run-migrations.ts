import { Sequelize } from 'sequelize';
import { config } from '../src/config/database.config';
import * as fs from 'fs';
import * as path from 'path';

async function runMigrations() {
  // Use the same config as the application
  const environment = process.env.ENVIRONMENT === 'dev' ? 'development' :
                     process.env.ENVIRONMENT === 'staging' ? 'test' :
                     process.env.ENVIRONMENT === 'prod' ? 'production' :
                     process.env.NODE_ENV || 'development';

  const dbConfig = {
    ...config[environment],
    host: process.env.DATABASE_HOST || config[environment].host,
    port: parseInt(process.env.DATABASE_PORT || config[environment].port?.toString() || '5432'),
    database: process.env.DATABASE_NAME || config[environment].database,
    username: process.env.DATABASE_USER || config[environment].username,
    password: process.env.DATABASE_PASSWORD || config[environment].password,
    dialect: config[environment].dialect,
  };

  console.log('Running migrations with config:', {
    host: dbConfig.host,
    port: dbConfig.port,
    database: dbConfig.database,
    username: dbConfig.username,
  });

  const sequelize = new Sequelize(dbConfig);

  try {
    await sequelize.authenticate();
    console.log('Database connection established successfully.');

    // Get all migration files
    const migrationsPath = path.join(__dirname, '../src/migrations');
    const migrationFiles = fs.readdirSync(migrationsPath)
      .filter(file => file.endsWith('.ts'))
      .sort();

    for (const file of migrationFiles) {
      console.log(`Running migration: ${file}`);
      const migration = require(path.join(migrationsPath, file));

      if (migration.up) {
        await migration.up(sequelize.getQueryInterface(), Sequelize);
        console.log(`Migration ${file} completed successfully.`);
      }
    }

    console.log('All migrations completed successfully.');
  } catch (error) {
    console.error('Error running migrations:', error);
    process.exit(1);
  } finally {
    await sequelize.close();
  }
}

runMigrations().catch(console.error);