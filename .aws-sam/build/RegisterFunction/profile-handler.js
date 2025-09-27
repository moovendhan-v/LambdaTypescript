/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 36:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.profileRepository = exports.ProfileRepository = void 0;
const base_repository_1 = __webpack_require__(228);
const models_1 = __webpack_require__(131);
class ProfileRepository extends base_repository_1.BaseRepository {
    constructor() {
        super(models_1.Profile);
    }
    async findByUserId(userId) {
        return await this.findOne({
            where: { userId }
        });
    }
}
exports.ProfileRepository = ProfileRepository;
exports.profileRepository = new ProfileRepository();


/***/ }),

/***/ 40:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.generateToken = generateToken;
exports.verifyToken = verifyToken;
const jsonwebtoken_1 = __importDefault(__webpack_require__(127));
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
function generateToken(payload) {
    return jsonwebtoken_1.default.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function verifyToken(token) {
    return jsonwebtoken_1.default.verify(token, JWT_SECRET);
}


/***/ }),

/***/ 127:
/***/ ((module) => {

module.exports = require("jsonwebtoken");

/***/ }),

/***/ 131:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Role = exports.Profile = exports.User = void 0;
var user_model_1 = __webpack_require__(963);
Object.defineProperty(exports, "User", ({ enumerable: true, get: function () { return user_model_1.User; } }));
var profile_model_1 = __webpack_require__(989);
Object.defineProperty(exports, "Profile", ({ enumerable: true, get: function () { return profile_model_1.Profile; } }));
var role_model_1 = __webpack_require__(676);
Object.defineProperty(exports, "Role", ({ enumerable: true, get: function () { return role_model_1.Role; } }));


/***/ }),

/***/ 214:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.userRepository = exports.UserRepository = void 0;
const sequelize_1 = __webpack_require__(241);
const base_repository_1 = __webpack_require__(228);
const models_1 = __webpack_require__(131);
class UserRepository extends base_repository_1.BaseRepository {
    constructor() {
        super(models_1.User);
    }
    async findByEmail(email, includePassword = false) {
        const attributes = includePassword
            ? undefined
            : { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] };
        return await this.findOne({
            where: { email },
            attributes,
        });
    }
    async findByEmailWithRoles(email) {
        return await this.findOne({
            where: { email },
            include: [
                {
                    model: models_1.Role,
                    as: 'roles',
                    attributes: ['id', 'name', 'permissions'],
                },
            ],
        });
    }
    async findByIdWithProfile(id) {
        return await this.findById(id, {
            include: [
                {
                    model: models_1.Profile,
                    as: 'profile',
                },
            ],
            attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] },
        });
    }
    async findUsersWithPagination(page = 1, limit = 10, search = '') {
        const offset = (page - 1) * limit;
        const whereClause = search
            ? {
                [sequelize_1.Op.or]: [
                    { firstName: { [sequelize_1.Op.iLike]: `%${search}%` } },
                    { lastName: { [sequelize_1.Op.iLike]: `%${search}%` } },
                    { email: { [sequelize_1.Op.iLike]: `%${search}%` } },
                ],
            }
            : {};
        const result = await this.findAndCountAll({
            where: whereClause,
            limit,
            offset,
            order: [['createdAt', 'DESC']],
            include: [
                {
                    model: models_1.Profile,
                    as: 'profile',
                    attributes: ['avatar', 'phoneNumber'],
                },
                {
                    model: models_1.Role,
                    as: 'roles',
                    attributes: ['name'],
                },
            ],
            attributes: { exclude: ['password', 'emailVerificationToken', 'passwordResetToken'] },
        });
        return {
            items: result.rows.map(user => user.toSafeObject()),
            pagination: {
                total: result.count,
                page,
                limit,
                totalPages: Math.ceil(result.count / limit),
            },
        };
    }
    async updateLastLogin(id) {
        return await this.update(id, { lastLoginAt: new Date() });
    }
    async setEmailVerified(id) {
        return await this.update(id, {
            emailVerified: true,
            emailVerificationToken: undefined,
        });
    }
    async findByVerificationToken(token) {
        return await this.findOne({
            where: { emailVerificationToken: token },
        });
    }
    async findByPasswordResetToken(token) {
        return await this.findOne({
            where: {
                passwordResetToken: token,
                passwordResetExpires: { [sequelize_1.Op.gt]: new Date() },
            },
        });
    }
}
exports.UserRepository = UserRepository;
exports.userRepository = new UserRepository();


/***/ }),

/***/ 228:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.BaseRepository = void 0;
const logger_1 = __webpack_require__(628);
class BaseRepository {
    constructor(model) {
        this.model = model;
    }
    async create(data, options = {}) {
        try {
            return await this.model.create(data, options);
        }
        catch (error) {
            logger_1.logger.error(`Error creating ${this.model.name}:`, error);
            throw error;
        }
    }
    async findById(id, options = {}) {
        try {
            return await this.model.findByPk(id, options);
        }
        catch (error) {
            logger_1.logger.error(`Error finding ${this.model.name} by ID:`, error);
            throw error;
        }
    }
    async findOne(options = {}) {
        try {
            return await this.model.findOne(options);
        }
        catch (error) {
            logger_1.logger.error(`Error finding ${this.model.name}:`, error);
            throw error;
        }
    }
    async findAll(options = {}) {
        try {
            return await this.model.findAll(options);
        }
        catch (error) {
            logger_1.logger.error(`Error finding all ${this.model.name}:`, error);
            throw error;
        }
    }
    async findAndCountAll(options = {}) {
        try {
            return await this.model.findAndCountAll(options);
        }
        catch (error) {
            logger_1.logger.error(`Error finding and counting ${this.model.name}:`, error);
            throw error;
        }
    }
    async update(id, data, options = { where: {} }) {
        try {
            const updateOptions = {
                ...options,
                where: {
                    ...(options.where || {}),
                    id,
                },
            };
            const [updatedRowsCount] = await this.model.update(data, updateOptions);
            if (updatedRowsCount === 0) {
                throw new Error(`${this.model.name} not found`);
            }
            const updatedRecord = await this.findById(id);
            if (!updatedRecord) {
                throw new Error(`${this.model.name} not found after update`);
            }
            return updatedRecord;
        }
        catch (error) {
            logger_1.logger.error(`Error updating ${this.model.name}:`, error);
            throw error;
        }
    }
    async delete(id, options = {}) {
        try {
            const deletedRowsCount = await this.model.destroy({
                where: { id },
                ...options,
            });
            if (deletedRowsCount === 0) {
                throw new Error(`${this.model.name} not found`);
            }
            return true;
        }
        catch (error) {
            logger_1.logger.error(`Error deleting ${this.model.name}:`, error);
            throw error;
        }
    }
    async bulkCreate(data, options = {}) {
        try {
            return await this.model.bulkCreate(data, options);
        }
        catch (error) {
            logger_1.logger.error(`Error bulk creating ${this.model.name}:`, error);
            throw error;
        }
    }
}
exports.BaseRepository = BaseRepository;


/***/ }),

/***/ 241:
/***/ ((module) => {

module.exports = require("sequelize");

/***/ }),

/***/ 371:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.updateProfileSchema = exports.refreshTokenSchema = exports.loginSchema = exports.registerSchema = void 0;
exports.validateData = validateData;
exports.validateUpdateProfile = validateUpdateProfile;
const joi_1 = __importDefault(__webpack_require__(600));
exports.registerSchema = joi_1.default.object({
    email: joi_1.default.string().email().required(),
    password: joi_1.default.string().min(8).required(),
    firstName: joi_1.default.string().min(2).max(50).required(),
    lastName: joi_1.default.string().min(2).max(50).required(),
});
exports.loginSchema = joi_1.default.object({
    email: joi_1.default.string().email().required(),
    password: joi_1.default.string().required(),
});
exports.refreshTokenSchema = joi_1.default.object({
    token: joi_1.default.string().required(),
});
exports.updateProfileSchema = joi_1.default.object({
    avatar: joi_1.default.string().uri().optional(),
    bio: joi_1.default.string().max(500).optional(),
    phoneNumber: joi_1.default.string().pattern(/^\+?[1-9]\d{1,14}$/).optional(),
    dateOfBirth: joi_1.default.date().iso().optional(),
    address: joi_1.default.object().optional(),
    preferences: joi_1.default.object().optional(),
});
function validateData(schema, data) {
    const { error, value } = schema.validate(data);
    if (error) {
        throw new Error(`Validation error: ${error.details[0].message}`);
    }
    return value;
}
function validateUpdateProfile(data) {
    const { error, value } = exports.updateProfileSchema.validate(data);
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


/***/ }),

/***/ 440:
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.errorResponse = exports.successResponse = void 0;
exports.createSuccessResponse = createSuccessResponse;
exports.createErrorResponse = createErrorResponse;
exports.createApiResponse = createApiResponse;
function createSuccessResponse(data, statusCode = 200, message) {
    const response = {
        success: true,
        data,
        ...(message && { message }),
    };
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        },
        body: JSON.stringify(response),
    };
}
function createErrorResponse(message, statusCode = 500, details) {
    const response = {
        success: false,
        error: {
            message,
            ...(details && { details }),
        },
    };
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
        },
        body: JSON.stringify(response),
    };
}
function createApiResponse(statusCode, headers, body) {
    return {
        statusCode,
        headers: {
            'Content-Type': 'application/json',
            ...headers,
        },
        body,
    };
}
exports.successResponse = createSuccessResponse;
exports.errorResponse = createErrorResponse;


/***/ }),

/***/ 465:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.requireAuth = requireAuth;
const jwt_helper_1 = __webpack_require__(40);
const logger_1 = __webpack_require__(628);
const response_helper_1 = __webpack_require__(440);
function requireAuth(handler) {
    return async (event, context) => {
        try {
            const authHeader = event.headers?.Authorization || event.headers?.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return (0, response_helper_1.errorResponse)('Authorization header missing or invalid', 401);
            }
            const token = authHeader.substring(7);
            const decoded = (0, jwt_helper_1.verifyToken)(token);
            const authenticatedEvent = {
                ...event,
                user: {
                    userId: decoded.userId,
                    email: decoded.email,
                    roles: decoded.roles || [],
                },
            };
            return await handler(authenticatedEvent, context);
        }
        catch (error) {
            logger_1.logger.error('Authentication failed', error);
            return (0, response_helper_1.errorResponse)('Invalid or expired token', 401);
        }
    };
}


/***/ }),

/***/ 600:
/***/ ((module) => {

module.exports = require("joi");

/***/ }),

/***/ 628:
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.withLogging = exports.logError = exports.createLogger = exports.Logger = exports.logger = exports.LogLevel = void 0;
exports.logPerformance = logPerformance;
var LogLevel;
(function (LogLevel) {
    LogLevel[LogLevel["ERROR"] = 0] = "ERROR";
    LogLevel[LogLevel["WARN"] = 1] = "WARN";
    LogLevel[LogLevel["INFO"] = 2] = "INFO";
    LogLevel[LogLevel["DEBUG"] = 3] = "DEBUG";
    LogLevel[LogLevel["TRACE"] = 4] = "TRACE";
})(LogLevel || (exports.LogLevel = LogLevel = {}));
class Logger {
    constructor(context, config) {
        this.performanceStart = new Map();
        this.config = {
            level: this.getLogLevel(),
            context: context || '',
            enablePerformanceTracking: "production" !== 'production',
            enableAwsMetadata: true,
            sanitizeFields: ['password', 'token', 'authorization', 'cookie', 'secret', 'key'],
            maxMetaSize: 10000,
            ...config,
        };
    }
    getLogLevel() {
        const envLevel = process.env.LOG_LEVEL?.toUpperCase() || 'INFO';
        switch (envLevel) {
            case 'ERROR':
                return LogLevel.ERROR;
            case 'WARN':
            case 'WARNING':
                return LogLevel.WARN;
            case 'INFO':
                return LogLevel.INFO;
            case 'DEBUG':
                return LogLevel.DEBUG;
            case 'TRACE':
                return LogLevel.TRACE;
            default:
                return LogLevel.INFO;
        }
    }
    shouldLog(level) {
        return level <= this.config.level;
    }
    sanitizeData(data) {
        if (!data || typeof data !== 'object') {
            return data;
        }
        if (Array.isArray(data)) {
            return data.map(item => this.sanitizeData(item));
        }
        const sanitized = {};
        for (const [key, value] of Object.entries(data)) {
            const lowerKey = key.toLowerCase();
            if (this.config.sanitizeFields.some(field => lowerKey.includes(field))) {
                sanitized[key] = '[REDACTED]';
            }
            else if (typeof value === 'object' && value !== null) {
                sanitized[key] = this.sanitizeData(value);
            }
            else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }
    limitMetaSize(meta) {
        const jsonString = JSON.stringify(meta);
        if (jsonString.length <= this.config.maxMetaSize) {
            return meta;
        }
        return {
            ...meta,
            _truncated: true,
            _originalSize: jsonString.length,
            _limit: this.config.maxMetaSize,
        };
    }
    getAwsMetadata() {
        if (!this.config.enableAwsMetadata) {
            return undefined;
        }
        return {
            region: process.env.AWS_REGION,
            functionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
            functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION,
            logGroup: process.env.AWS_LAMBDA_LOG_GROUP_NAME,
            logStream: process.env.AWS_LAMBDA_LOG_STREAM_NAME,
        };
    }
    createLogEntry(level, message, meta, error) {
        const entry = {
            timestamp: new Date().toISOString(),
            level: level.toUpperCase(),
            message,
            context: this.config.context,
            requestId: process.env.AWS_REQUEST_ID,
        };
        const awsMetadata = this.getAwsMetadata();
        if (awsMetadata) {
            entry.aws = awsMetadata;
        }
        if (meta) {
            const sanitizedMeta = this.sanitizeData(meta);
            entry.meta = this.limitMetaSize(sanitizedMeta);
        }
        if (error) {
            entry.error = {
                name: error.name,
                message: error.message,
                stack: error.stack,
                code: error.code,
            };
        }
        if (this.config.enablePerformanceTracking) {
            const memUsage = process.memoryUsage();
            entry.performance = {
                memory: Math.round(memUsage.heapUsed / 1024 / 1024),
            };
        }
        return entry;
    }
    log(level, levelName, message, meta, error) {
        if (!this.shouldLog(level)) {
            return;
        }
        const logEntry = this.createLogEntry(levelName, message, meta, error);
        switch (level) {
            case LogLevel.ERROR:
                console.error(JSON.stringify(logEntry));
                break;
            case LogLevel.WARN:
                console.warn(JSON.stringify(logEntry));
                break;
            case LogLevel.INFO:
                console.info(JSON.stringify(logEntry));
                break;
            case LogLevel.DEBUG:
            case LogLevel.TRACE:
                console.log(JSON.stringify(logEntry));
                break;
            default:
                console.log(JSON.stringify(logEntry));
        }
    }
    error(message, error) {
        if (error instanceof Error) {
            this.log(LogLevel.ERROR, 'ERROR', message, undefined, error);
        }
        else {
            this.log(LogLevel.ERROR, 'ERROR', message, error);
        }
    }
    warn(message, meta) {
        this.log(LogLevel.WARN, 'WARN', message, meta);
    }
    info(message, meta) {
        this.log(LogLevel.INFO, 'INFO', message, meta);
    }
    debug(message, meta) {
        this.log(LogLevel.DEBUG, 'DEBUG', message, meta);
    }
    trace(message, meta) {
        this.log(LogLevel.TRACE, 'TRACE', message, meta);
    }
    startTimer(label) {
        if (this.config.enablePerformanceTracking) {
            this.performanceStart.set(label, Date.now());
        }
    }
    endTimer(label, message) {
        if (!this.config.enablePerformanceTracking) {
            return;
        }
        const startTime = this.performanceStart.get(label);
        if (startTime) {
            const duration = Date.now() - startTime;
            this.performanceStart.delete(label);
            const logMessage = message || `Performance: ${label}`;
            const entry = this.createLogEntry('INFO', logMessage);
            entry.performance = {
                ...entry.performance,
                duration,
            };
            console.info(JSON.stringify(entry));
        }
    }
    logRequest(req) {
        this.info('HTTP Request', {
            http: {
                method: req.method,
                url: req.url,
                headers: this.sanitizeData(req.headers),
                query: req.query,
                params: req.params,
                hasBody: !!req.body,
            },
        });
    }
    logResponse(res) {
        const level = res.statusCode && res.statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO;
        const levelName = level === LogLevel.WARN ? 'WARN' : 'INFO';
        this.log(level, levelName, 'HTTP Response', {
            http: {
                statusCode: res.statusCode,
                headers: this.sanitizeData(res.headers),
                hasBody: !!res.body,
                duration: res.duration,
            },
        });
    }
    logQuery(query) {
        this.debug('Database Query', {
            database: {
                operation: query.operation,
                table: query.table,
                sql: query.sql,
                params: this.sanitizeData(query.params),
                duration: query.duration,
            },
        });
    }
    logUserAction(userId, action, resource, meta) {
        this.info('User Action', {
            user: {
                id: userId,
                action,
                resource,
            },
            ...meta,
        });
    }
    logSecurityEvent(event) {
        const level = event.severity === 'critical' || event.severity === 'high' ? LogLevel.ERROR : LogLevel.WARN;
        const levelName = level === LogLevel.ERROR ? 'ERROR' : 'WARN';
        this.log(level, levelName, `Security Event: ${event.type}`, {
            security: {
                type: event.type,
                severity: event.severity,
                userId: event.userId,
                ip: event.ip,
                userAgent: event.userAgent,
                details: event.details,
            },
        });
    }
    child(context, meta) {
        const childContext = this.config.context ? `${this.config.context}:${context}` : context;
        const childLogger = new Logger(childContext, this.config);
        if (meta) {
            const originalLog = childLogger.log.bind(childLogger);
            childLogger.log = (level, levelName, message, logMeta, error) => {
                const combinedMeta = { ...meta, ...logMeta };
                originalLog(level, levelName, message, combinedMeta, error);
            };
        }
        return childLogger;
    }
    setCorrelationId(correlationId) {
        process.env.CORRELATION_ID = correlationId;
    }
    getCorrelationId() {
        return process.env.CORRELATION_ID;
    }
    logLambdaStart(event, context) {
        this.info('Lambda Invocation Start', {
            lambda: {
                functionName: context.functionName,
                functionVersion: context.functionVersion,
                requestId: context.awsRequestId,
                remainingTime: context.getRemainingTimeInMillis(),
                memoryLimit: context.memoryLimitInMB,
                eventType: this.getEventType(event),
            },
        });
    }
    logLambdaEnd(duration, memory) {
        this.info('Lambda Invocation End', {
            lambda: {
                duration,
                memory,
            },
        });
    }
    getEventType(event) {
        if (event.httpMethod)
            return 'API Gateway';
        if (event.Records) {
            if (event.Records[0]?.eventSource === 'aws:s3')
                return 'S3';
            if (event.Records[0]?.EventSource === 'aws:sns')
                return 'SNS';
            if (event.Records[0]?.eventSource === 'aws:sqs')
                return 'SQS';
            if (event.Records[0]?.eventSource === 'aws:dynamodb')
                return 'DynamoDB';
        }
        if (event.source === 'aws.events')
            return 'EventBridge';
        return 'Unknown';
    }
}
exports.Logger = Logger;
exports.logger = new Logger('LambdaApp');
const createLogger = (context, config) => {
    return new Logger(context, config);
};
exports.createLogger = createLogger;
function logPerformance(label) {
    return function (target, propertyKey, descriptor) {
        const originalMethod = descriptor.value;
        const perfLabel = label || `${target.constructor.name}.${propertyKey}`;
        descriptor.value = async function (...args) {
            exports.logger.startTimer(perfLabel);
            try {
                const result = await originalMethod.apply(this, args);
                exports.logger.endTimer(perfLabel);
                return result;
            }
            catch (error) {
                exports.logger.endTimer(perfLabel);
                throw error;
            }
        };
        return descriptor;
    };
}
const logError = (error, context, meta) => {
    const contextLogger = context ? exports.logger.child(context) : exports.logger;
    contextLogger.error(error.message, error);
    if (meta) {
        contextLogger.debug('Error context', meta);
    }
};
exports.logError = logError;
const withLogging = (handler) => {
    return async (event, context) => {
        const requestLogger = exports.logger.child('Handler', { requestId: context.awsRequestId });
        const startTime = Date.now();
        requestLogger.logLambdaStart(event, context);
        try {
            const result = await handler(event, context);
            const duration = Date.now() - startTime;
            requestLogger.logLambdaEnd(duration);
            return result;
        }
        catch (error) {
            const duration = Date.now() - startTime;
            requestLogger.error('Lambda execution failed', error);
            requestLogger.logLambdaEnd(duration);
            throw error;
        }
    };
};
exports.withLogging = withLogging;


/***/ }),

/***/ 676:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Role = void 0;
const sequelize_1 = __webpack_require__(241);
const database_config_1 = __webpack_require__(828);
const user_model_1 = __webpack_require__(963);
class Role extends sequelize_1.Model {
}
exports.Role = Role;
Role.init({
    id: {
        type: sequelize_1.DataTypes.UUID,
        defaultValue: sequelize_1.DataTypes.UUIDV4,
        primaryKey: true,
    },
    name: {
        type: sequelize_1.DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    description: {
        type: sequelize_1.DataTypes.TEXT,
    },
    permissions: {
        type: sequelize_1.DataTypes.JSON,
        defaultValue: [],
    },
}, {
    sequelize: database_config_1.sequelize,
    modelName: 'Role',
    tableName: 'roles',
});
Role.belongsToMany(user_model_1.User, { through: 'user_roles', foreignKey: 'roleId', as: 'users' });
user_model_1.User.belongsToMany(Role, { through: 'user_roles', foreignKey: 'userId', as: 'roles' });
exports["default"] = Role;


/***/ }),

/***/ 709:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.profileService = exports.ProfileService = void 0;
const profile_repository_1 = __webpack_require__(36);
const user_repository_1 = __webpack_require__(214);
const logger_1 = __webpack_require__(628);
class ProfileService {
    async getProfileByUserId(userId) {
        logger_1.logger.info('Getting profile for user', { userId });
        const profile = await profile_repository_1.profileRepository.findByUserId(userId);
        if (!profile) {
            throw new Error('Profile not found');
        }
        return profile.toJSON();
    }
    async updateProfile(userId, updateData) {
        logger_1.logger.info('Updating profile for user', { userId });
        const user = await user_repository_1.userRepository.findById(userId);
        if (!user) {
            throw new Error('User not found');
        }
        const existingProfile = await profile_repository_1.profileRepository.findByUserId(userId);
        if (!existingProfile) {
            throw new Error('Profile not found');
        }
        const updatedProfile = await profile_repository_1.profileRepository.update(existingProfile.id, updateData);
        return updatedProfile.toJSON();
    }
}
exports.ProfileService = ProfileService;
exports.profileService = new ProfileService();


/***/ }),

/***/ 828:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.config = exports.sequelize = exports.getSequelizeInstance = void 0;
const sequelize_1 = __webpack_require__(241);
const logger_1 = __webpack_require__(628);
const config = {
    development: {
        host: 'localhost',
        port: 5432,
        database: 'lambda_dev',
        username: 'postgres',
        password: 'postgres',
        dialect: 'postgres',
        logging: (msg) => logger_1.logger.debug(msg),
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
        host: process.env.DB_HOST,
        port: parseInt(process.env.DB_PORT || '5432'),
        database: process.env.DB_NAME,
        username: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
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
exports.config = config;
const environment = "production" || 0;
const dbConfig = config[environment];
let sequelizeInstance;
const getSequelizeInstance = () => {
    if (!sequelizeInstance) {
        sequelizeInstance = new sequelize_1.Sequelize(dbConfig);
    }
    return sequelizeInstance;
};
exports.getSequelizeInstance = getSequelizeInstance;
exports.sequelize = (0, exports.getSequelizeInstance)();


/***/ }),

/***/ 898:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.withErrorHandling = withErrorHandling;
const logger_1 = __webpack_require__(628);
const response_helper_1 = __webpack_require__(440);
function withErrorHandling(handler) {
    return async (event, context) => {
        try {
            return await handler(event, context);
        }
        catch (error) {
            logger_1.logger.error('Handler error', error);
            if (error instanceof Error) {
                if (error.message.includes('Validation failed')) {
                    return (0, response_helper_1.errorResponse)(error.message, 400);
                }
                if (error.message.includes('not found')) {
                    return (0, response_helper_1.errorResponse)(error.message, 404);
                }
                if (error.message.includes('Unauthorized') || error.message.includes('Invalid token')) {
                    return (0, response_helper_1.errorResponse)(error.message, 401);
                }
                if (error.message.includes('Forbidden') || error.message.includes('not allowed')) {
                    return (0, response_helper_1.errorResponse)(error.message, 403);
                }
            }
            return (0, response_helper_1.errorResponse)('Internal server error', 500);
        }
    };
}


/***/ }),

/***/ 963:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.User = void 0;
const sequelize_1 = __webpack_require__(241);
const database_config_1 = __webpack_require__(828);
class User extends sequelize_1.Model {
    toSafeObject() {
        const { password, emailVerificationToken, passwordResetToken, passwordResetExpires, ...safeUser } = this.toJSON();
        return safeUser;
    }
    async validatePassword(password) {
        return true;
    }
}
exports.User = User;
User.init({
    id: {
        type: sequelize_1.DataTypes.UUID,
        defaultValue: sequelize_1.DataTypes.UUIDV4,
        primaryKey: true,
    },
    email: {
        type: sequelize_1.DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: sequelize_1.DataTypes.STRING,
        allowNull: false,
    },
    firstName: {
        type: sequelize_1.DataTypes.STRING,
        allowNull: false,
    },
    lastName: {
        type: sequelize_1.DataTypes.STRING,
        allowNull: false,
    },
    isActive: {
        type: sequelize_1.DataTypes.BOOLEAN,
        defaultValue: true,
    },
    emailVerified: {
        type: sequelize_1.DataTypes.BOOLEAN,
        defaultValue: false,
    },
    emailVerificationToken: {
        type: sequelize_1.DataTypes.STRING,
    },
    passwordResetToken: {
        type: sequelize_1.DataTypes.STRING,
    },
    passwordResetExpires: {
        type: sequelize_1.DataTypes.DATE,
    },
    lastLoginAt: {
        type: sequelize_1.DataTypes.DATE,
    },
}, {
    sequelize: database_config_1.sequelize,
    modelName: 'User',
    tableName: 'users',
});
exports["default"] = User;


/***/ }),

/***/ 989:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Profile = void 0;
const sequelize_1 = __webpack_require__(241);
const database_config_1 = __webpack_require__(828);
const user_model_1 = __webpack_require__(963);
class Profile extends sequelize_1.Model {
}
exports.Profile = Profile;
Profile.init({
    id: {
        type: sequelize_1.DataTypes.UUID,
        defaultValue: sequelize_1.DataTypes.UUIDV4,
        primaryKey: true,
    },
    userId: {
        type: sequelize_1.DataTypes.UUID,
        allowNull: false,
        references: {
            model: 'users',
            key: 'id',
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
    },
    avatar: {
        type: sequelize_1.DataTypes.STRING(500),
    },
    bio: {
        type: sequelize_1.DataTypes.TEXT,
    },
    phoneNumber: {
        type: sequelize_1.DataTypes.STRING(15),
        validate: {
            is: /^\+?[1-9]\d{1,14}$/,
        },
    },
    dateOfBirth: {
        type: sequelize_1.DataTypes.DATEONLY,
    },
    address: {
        type: sequelize_1.DataTypes.JSON,
    },
    preferences: {
        type: sequelize_1.DataTypes.JSON,
        defaultValue: {
            theme: 'light',
            notifications: true,
            language: 'en',
        },
    },
}, {
    sequelize: database_config_1.sequelize,
    modelName: 'Profile',
    tableName: 'profiles',
});
Profile.belongsTo(user_model_1.User, { foreignKey: 'userId', as: 'user' });
user_model_1.User.hasOne(Profile, { foreignKey: 'userId', as: 'profile' });
exports["default"] = Profile;


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it uses a non-standard name for the exports (exports).
(() => {
var exports = __webpack_exports__;

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.updateProfile = exports.getProfile = void 0;
const profile_service_1 = __webpack_require__(709);
const validation_1 = __webpack_require__(371);
const response_helper_1 = __webpack_require__(440);
const error_handler_middleware_1 = __webpack_require__(898);
const auth_middleware_1 = __webpack_require__(465);
const logger_1 = __webpack_require__(628);
const getProfileHandler = async (event) => {
    logger_1.logger.info('Get profile request', { path: event.path });
    const userId = event.user?.userId;
    if (!userId) {
        return (0, response_helper_1.errorResponse)('Unauthorized', 401);
    }
    const profile = await profile_service_1.profileService.getProfileByUserId(userId);
    return (0, response_helper_1.successResponse)({ profile }, 200);
};
const updateProfileHandler = async (event) => {
    logger_1.logger.info('Update profile request', { path: event.path });
    const userId = event.user?.userId;
    if (!userId) {
        return (0, response_helper_1.errorResponse)('Unauthorized', 401);
    }
    const updateData = JSON.parse(event.body || '{}');
    const validation = (0, validation_1.validateUpdateProfile)(updateData);
    if (!validation.isValid) {
        return (0, response_helper_1.errorResponse)('Validation failed', 400, validation.errors);
    }
    const profile = await profile_service_1.profileService.updateProfile(userId, validation.data);
    return (0, response_helper_1.successResponse)({
        message: 'Profile updated successfully',
        profile,
    }, 200);
};
exports.getProfile = (0, auth_middleware_1.requireAuth)((0, error_handler_middleware_1.withErrorHandling)(getProfileHandler));
exports.updateProfile = (0, auth_middleware_1.requireAuth)((0, error_handler_middleware_1.withErrorHandling)(updateProfileHandler));

})();

module.exports = __webpack_exports__;
/******/ })()
;