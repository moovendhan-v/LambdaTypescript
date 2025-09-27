import { DataTypes, Model } from 'sequelize';
import { sequelize } from '@/config/database.config';
import { User } from './user.model';

export class Role extends Model {
  public id!: string;
  public name!: string;
  public description?: string;
  public permissions?: string[];
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;

  // Association mixins
  public readonly users?: User[];
}

Role.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    description: {
      type: DataTypes.TEXT,
    },
    permissions: {
      type: DataTypes.JSON,
      defaultValue: [],
    },
  },
  {
    sequelize,
    modelName: 'Role',
    tableName: 'roles',
  }
);

// Associations
Role.belongsToMany(User, { through: 'user_roles', foreignKey: 'roleId', as: 'users' });
User.belongsToMany(Role, { through: 'user_roles', foreignKey: 'userId', as: 'roles' });

export default Role;