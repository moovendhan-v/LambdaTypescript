import { QueryInterface, DataTypes } from 'sequelize';

export default {
  up: async (queryInterface: QueryInterface) => {
    await queryInterface.createTable('profiles', {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
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
        allowNull: true,
      },
      bio: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
      phoneNumber: {
        type: DataTypes.STRING(15),
        allowNull: true,
      },
      dateOfBirth: {
        type: DataTypes.DATEONLY,
        allowNull: true,
      },
      address: {
        type: DataTypes.JSON,
        allowNull: true,
      },
      preferences: {
        type: DataTypes.JSON,
        allowNull: true,
        defaultValue: {
          theme: 'light',
          notifications: true,
          language: 'en',
        },
      },
      createdAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      updatedAt: {
        type: DataTypes.DATE,
        allowNull: false,
      },
    });

    // Add unique constraint on userId
    await queryInterface.addIndex('profiles', ['userId'], {
      unique: true,
      name: 'unique_user_profile',
    });
  },

  down: async (queryInterface: QueryInterface) => {
    await queryInterface.dropTable('profiles');
  },
};