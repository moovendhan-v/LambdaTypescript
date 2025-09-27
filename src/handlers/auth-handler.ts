// src/handlers/auth-handler.ts
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { authService } from '@/services/auth.service';
import { IRegisterRequest } from '@/interfaces/auth.interface';
import { logger } from '@/utils/logger';

export const register = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
    try {
        const { email, password, firstName, lastName } = JSON.parse(event.body || '{}');
        const user = await authService.register({ email, password, firstName, lastName } as IRegisterRequest);
        return {
            statusCode: 201,
            body: JSON.stringify(user),
        };
    } catch (error) {
        logger.error('Registration failed', error as Error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Internal Server Error' }),
        };
    }
};

