import { DataTypes, Model } from 'sequelize';
import { sequelize } from '@/config/database.config';
import { User } from './user.model';

export interface Address {
  street?: string;
  city?: string;
  state?: string;
  country?: string;
  zipCode?: string;
}

export interface Preferences {
  theme?: 'light' | 'dark' | 'auto';
  notifications?: boolean;
  language?: string;
  timezone?: string;
}

export class Profile extends Model {
  public id!: string;
  public userId!: string;
  public avatar?: string;
  public bio?: string;
  public phoneNumber?: string;
  public dateOfBirth?: Date;
  public address?: Address;
  public preferences?: Preferences;
  public readonly createdAt!: Date;
  public readonly updatedAt!: Date;

  // Association mixins
  public readonly user?: User;
}

Profile.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    userId: {
      type: DataTypes.UUID,
      allowNull: false,
      references: {
        model: 'users',
        key: 'id',
      },
      onDelete: 'CASCADE',
      onUpdate: 'CASCADE',
    },
    avatar: {
      type: DataTypes.STRING(500),
    },
    bio: {
      type: DataTypes.TEXT,
    },
    phoneNumber: {
      type: DataTypes.STRING(15),
      validate: {
        is: /^\+?[1-9]\d{1,14}$/,
      },
    },
    dateOfBirth: {
      type: DataTypes.DATEONLY,
    },
    address: {
      type: DataTypes.JSON,
    },
    preferences: {
      type: DataTypes.JSON,
      defaultValue: {
        theme: 'light',
        notifications: true,
        language: 'en',
      },
    },
  },
  {
    sequelize,
    modelName: 'Profile',
    tableName: 'profiles',
  }
);

// Associations
Profile.belongsTo(User, { foreignKey: 'userId', as: 'user' });
User.hasOne(Profile, { foreignKey: 'userId', as: 'profile' });

export default Profile;