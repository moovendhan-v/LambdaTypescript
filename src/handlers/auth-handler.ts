// src/handlers/auth-handler.ts
import { APIGatewayProxyEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { Effect } from 'effect';
import { authService } from '@/services/auth.service';
import { IRegisterRequest } from '@/interfaces/auth.interface';
import { logger } from '@/utils/logger';
// import { DatabaseError, ValidationError, ConflictError } from '@/types/effect.types';

export const register = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
    logger.info('Environment variables in Lambda:', {
        ENVIRONMENT: process.env.ENVIRONMENT,
        DATABASE_HOST: process.env.DATABASE_HOST,
        DATABASE_PORT: process.env.DATABASE_PORT,
        DATABASE_NAME: process.env.DATABASE_NAME,
        DATABASE_USER: process.env.DATABASE_USER,
    });

    return Effect.runPromise(
        Effect.gen(function* () {
            const { email, password, firstName, lastName } = JSON.parse(event.body || '{}');
            const user = yield* authService.register({ email, password, firstName, lastName } as IRegisterRequest);
            return {
                statusCode: 201,
                body: JSON.stringify(user),
            };
        }).pipe(
            Effect.catchAll((error) => {
                logger.error('Registration failed', error);
                return Effect.succeed({
                    statusCode: 500,
                    body: JSON.stringify({ error: 'Internal Server Error' }),
                });
            })
        )
    );
};

/* __webpack_exports__ */ export const login = async (event: APIGatewayProxyEvent, context: Context): Promise<APIGatewayProxyResult> => {
    return Effect.runPromise(
        Effect.gen(function* () {
            const { email, password } = JSON.parse(event.body || '{}');
            const result = yield* authService.login(email, password);
            return {
                statusCode: 200,
                body: JSON.stringify(result),
            };
        }).pipe(
            Effect.catchAll((error) => {
                logger.error('Login failed', error);
                return Effect.succeed({
                    statusCode: 401,
                    body: JSON.stringify({ error: 'Invalid credentials' }),
                });
            })
        )
    );
};

// Ensure both exports are preserved
export const handlers = { register, login };

// Prevent tree shaking
console.log(register, login);

