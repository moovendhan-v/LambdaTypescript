import Joi from 'joi';

// Validation schemas
export const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

export const refreshTokenSchema = Joi.object({
  token: Joi.string().required(),
});

export const updateProfileSchema = Joi.object({
  avatar: Joi.string().uri().optional(),
  bio: Joi.string().max(500).optional(),
  phoneNumber: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).optional(),
  dateOfBirth: Joi.date().iso().optional(),
  address: Joi.object().optional(),
  preferences: Joi.object().optional(),
});

// Validation function
export function validateData<T>(schema: Joi.ObjectSchema, data: any): T {
  const { error, value } = schema.validate(data);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
}

export function validateUpdateProfile(data: any): { isValid: boolean; data?: any; errors?: string[] } {
  const { error, value } = updateProfileSchema.validate(data);
  if (error) {
    return {
      isValid: false,
      errors: error.details.map(detail => detail.message),
    };
  }
  return {
    isValid: true,
    data: value,
  };
}