// src/repositories/base.repository.ts
import { Model, ModelStatic, FindOptions, DestroyOptions, CreateOptions, UpdateOptions } from 'sequelize';
import { logger } from '@/utils/logger';

export abstract class BaseRepository<T extends Model> {
  protected model: ModelStatic<T>;

  constructor(model: ModelStatic<T>) {
    this.model = model;
  }

  async create(data: any, options: CreateOptions<T['_attributes']> = {}): Promise<T> {
    try {
      return await this.model.create(data, options);
    } catch (error) {
      logger.error(`Error creating ${this.model.name}:`, error as Error);
      throw error;
    }
  }

  async findById(id: string, options: FindOptions<T['_attributes']> = {}): Promise<T | null> {
    try {
      return await this.model.findByPk(id, options);
    } catch (error) {
      logger.error(`Error finding ${this.model.name} by ID:`, error as Error);
      throw error;
    }
  }

  async findOne(options: FindOptions<T['_attributes']> = {}): Promise<T | null> {
    try {
      return await this.model.findOne(options);
    } catch (error) {
      logger.error(`Error finding ${this.model.name}:`, error as Error);
      throw error;
    }
  }

  async findAll(options: FindOptions<T['_attributes']> = {}): Promise<T[]> {
    try {
      return await this.model.findAll(options);
    } catch (error) {
      logger.error(`Error finding all ${this.model.name}:`, error as Error);
      throw error;
    }
  }

  async findAndCountAll(options: FindOptions<T['_attributes']> = {}): Promise<{ rows: T[]; count: number }> {
    try {
      return await this.model.findAndCountAll(options);
    } catch (error) {
      logger.error(`Error finding and counting ${this.model.name}:`, error as Error);
      throw error;
    }
  }

  async update(id: string, data: Partial<T['_attributes']>, options: UpdateOptions<T['_attributes']> = { where: {} }): Promise<T> {
    try {
      const updateOptions = {
        ...options,
        where: {
          ...((options as any).where || {}),
          id,
        },
      } as UpdateOptions<T['_attributes']>;
      const [updatedRowsCount] = await this.model.update(data, updateOptions);

      if (updatedRowsCount === 0) {
        throw new Error(`${this.model.name} not found`);
      }

      const updatedRecord = await this.findById(id);
      if (!updatedRecord) {
        throw new Error(`${this.model.name} not found after update`);
      }

      return updatedRecord;
    } catch (error) {
      logger.error(`Error updating ${this.model.name}:`, error as Error);
      throw error;
    }
  }

  async delete(id: string, options: DestroyOptions<T['_attributes']> = {}): Promise<boolean> {
    try {
      const deletedRowsCount = await this.model.destroy({
        where: { id } as any,
        ...options,
      });

      if (deletedRowsCount === 0) {
        throw new Error(`${this.model.name} not found`);
      }

      return true;
    } catch (error) {
      logger.error(`Error deleting ${this.model.name}:`, error as Error);
      throw error;
    }
  }

  async bulkCreate(data: any[], options: CreateOptions<T['_attributes']> = {}): Promise<T[]> {
    try {
      return await this.model.bulkCreate(data, options);
    } catch (error) {
      logger.error(`Error bulk creating ${this.model.name}:`, error as Error);
      throw error;
    }
  }
}