// src/repositories/base.repository.ts
import { Model, ModelStatic, FindOptions, DestroyOptions, CreateOptions, UpdateOptions } from 'sequelize';
import { Effect } from 'effect';
import { logger } from '@/utils/logger';
import { DatabaseError, NotFoundError } from '@/types/effect.types';

export abstract class BaseRepository<T extends Model> {
  protected model: ModelStatic<T>;

  constructor(model: ModelStatic<T>) {
    this.model = model;
  }

  create(data: any, options: CreateOptions<T['_attributes']> = {}): Effect.Effect<T, DatabaseError> {
    return Effect.tryPromise({
      try: () => this.model.create(data, options),
      catch: (error) => {
        logger.error(`Error creating ${this.model.name}:`, error as Error);
        return new DatabaseError({ message: `Failed to create ${this.model.name}`, cause: error });
      },
    });
  }

  findById(id: string, options: FindOptions<T['_attributes']> = {}): Effect.Effect<T | null, DatabaseError> {
    return Effect.tryPromise({
      try: () => this.model.findByPk(id, options),
      catch: (error) => {
        logger.error(`Error finding ${this.model.name} by ID:`, error as Error);
        return new DatabaseError({ message: `Failed to find ${this.model.name} by ID: ${id}`, cause: error });
      },
    });
  }

  findOne(options: FindOptions<T['_attributes']> = {}): Effect.Effect<T | null, DatabaseError> {
    return Effect.tryPromise({
      try: () => this.model.findOne(options),
      catch: (error) => {
        logger.error(`Error finding ${this.model.name}:`, error as Error);
        return new DatabaseError({ message: `Failed to find ${this.model.name}`, cause: error });
      },
    });
  }

  findAll(options: FindOptions<T['_attributes']> = {}): Effect.Effect<T[], DatabaseError> {
    return Effect.tryPromise({
      try: () => this.model.findAll(options),
      catch: (error) => {
        logger.error(`Error finding all ${this.model.name}:`, error as Error);
        return new DatabaseError({ message: `Failed to find all ${this.model.name}`, cause: error });
      },
    });
  }

  findAndCountAll(options: FindOptions<T['_attributes']> = {}): Effect.Effect<{ rows: T[]; count: number }, DatabaseError> {
    return Effect.tryPromise({
      try: () => this.model.findAndCountAll(options),
      catch: (error) => {
        logger.error(`Error finding and counting ${this.model.name}:`, error as Error);
        return new DatabaseError({ message: `Failed to find and count ${this.model.name}`, cause: error });
      },
    });
  }

  update(id: string, data: Partial<T['_attributes']>, options: UpdateOptions<T['_attributes']> = { where: {} }): Effect.Effect<T, DatabaseError | NotFoundError> {
    return Effect.gen(function* (this: BaseRepository<T>) {
      const self = this;
      const updateOptions = {
        ...options,
        where: {
          ...((options as any).where || {}),
          id,
        },
      } as UpdateOptions<T['_attributes']>;

      const updateResult = yield* Effect.tryPromise({
        try: () => self.model.update(data, updateOptions),
        catch: (error) => new DatabaseError({ message: `Failed to update ${self.model.name}`, cause: error }),
      });

      const updatedRowsCount = updateResult[0];

      if (updatedRowsCount === 0) {
        return yield* Effect.fail(new NotFoundError({ message: `${self.model.name} not found` }));
      }

      const updatedRecord = yield* self.findById(id);
      if (!updatedRecord) {
        return yield* Effect.fail(new NotFoundError({ message: `${self.model.name} not found after update` }));
      }

      return updatedRecord;
    }.bind(this)) as Effect.Effect<T, DatabaseError | NotFoundError>;
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