// src/utils/logger.ts
export enum LogLevel {
    ERROR = 0,
    WARN = 1,
    INFO = 2,
    DEBUG = 3,
    TRACE = 4,
  }
  
  interface LogEntry {
    timestamp: string;
    level: string;
    message: string;
    context?: string;
    requestId?: string;
    userId?: string;
    correlationId?: string;
    meta?: Record<string, any>;
    error?: {
      name: string;
      message: string;
      stack?: string;
      code?: string | number;
    };
    performance?: {
      duration?: number;
      memory?: number;
    };
    aws?: {
      region?: string;
      functionName?: string;
      functionVersion?: string;
      logGroup?: string;
      logStream?: string;
    };
  }
  
  interface LoggerConfig {
    level: LogLevel;
    context?: string;
    enablePerformanceTracking: boolean;
    enableAwsMetadata: boolean;
    sanitizeFields: string[];
    maxMetaSize: number;
  }
  
  class Logger {
    private config: LoggerConfig;
    private performanceStart: Map<string, number> = new Map();
  
    constructor(context?: string, config?: Partial<LoggerConfig>) {
      this.config = {
        level: this.getLogLevel(),
        context: context || '',
        enablePerformanceTracking: process.env.NODE_ENV !== 'production',
        enableAwsMetadata: true,
        sanitizeFields: ['password', 'token', 'authorization', 'cookie', 'secret', 'key'],
        maxMetaSize: 10000, // 10KB limit for metadata
        ...config,
      };
    }
  
    private getLogLevel(): LogLevel {
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
  
    private shouldLog(level: LogLevel): boolean {
      return level <= this.config.level;
    }
  
    private sanitizeData(data: any): any {
      if (!data || typeof data !== 'object') {
        return data;
      }
  
      if (Array.isArray(data)) {
        return data.map(item => this.sanitizeData(item));
      }
  
      const sanitized: any = {};
      
      for (const [key, value] of Object.entries(data)) {
        const lowerKey = key.toLowerCase();
        
        if (this.config.sanitizeFields.some(field => lowerKey.includes(field))) {
          sanitized[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
          sanitized[key] = this.sanitizeData(value);
        } else {
          sanitized[key] = value;
        }
      }
  
      return sanitized;
    }
  
    private limitMetaSize(meta: any): any {
      const jsonString = JSON.stringify(meta);
      
      if (jsonString.length <= this.config.maxMetaSize) {
        return meta;
      }
  
      // If too large, return truncated version
      return {
        ...meta,
        _truncated: true,
        _originalSize: jsonString.length,
        _limit: this.config.maxMetaSize,
      };
    }
  
    private getAwsMetadata(): LogEntry['aws'] {
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
  
    private createLogEntry(
      level: string,
      message: string,
      meta?: Record<string, any>,
      error?: Error
    ): LogEntry {
      const entry: LogEntry = {
        timestamp: new Date().toISOString(),
        level: level.toUpperCase(),
        message,
        context: this.config.context,
        requestId: process.env.AWS_REQUEST_ID,
      };
  
      // Add AWS metadata
      const awsMetadata = this.getAwsMetadata();
      if (awsMetadata) {
        entry.aws = awsMetadata;
      }
  
      // Add sanitized meta
      if (meta) {
        const sanitizedMeta = this.sanitizeData(meta);
        entry.meta = this.limitMetaSize(sanitizedMeta);
      }
  
      // Add error information
      if (error) {
        entry.error = {
          name: error.name,
          message: error.message,
          stack: error.stack,
          code: (error as any).code,
        };
      }
  
      // Add memory usage if performance tracking is enabled
      if (this.config.enablePerformanceTracking) {
        const memUsage = process.memoryUsage();
        entry.performance = {
          memory: Math.round(memUsage.heapUsed / 1024 / 1024), // MB
        };
      }
  
      return entry;
    }
  
    private log(level: LogLevel, levelName: string, message: string, meta?: Record<string, any>, error?: Error): void {
      if (!this.shouldLog(level)) {
        return;
      }
  
      const logEntry = this.createLogEntry(levelName, message, meta, error);
      
      // Use console methods for proper CloudWatch log level handling
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
  
    // Public logging methods
    error(message: string, error?: Error | Record<string, any>): void {
      if (error instanceof Error) {
        this.log(LogLevel.ERROR, 'ERROR', message, undefined, error);
      } else {
        this.log(LogLevel.ERROR, 'ERROR', message, error);
      }
    }
  
    warn(message: string, meta?: Record<string, any>): void {
      this.log(LogLevel.WARN, 'WARN', message, meta);
    }
  
    info(message: string, meta?: Record<string, any>): void {
      this.log(LogLevel.INFO, 'INFO', message, meta);
    }
  
    debug(message: string, meta?: Record<string, any>): void {
      this.log(LogLevel.DEBUG, 'DEBUG', message, meta);
    }
  
    trace(message: string, meta?: Record<string, any>): void {
      this.log(LogLevel.TRACE, 'TRACE', message, meta);
    }
  
    // Performance tracking methods
    startTimer(label: string): void {
      if (this.config.enablePerformanceTracking) {
        this.performanceStart.set(label, Date.now());
      }
    }
  
    endTimer(label: string, message?: string): void {
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
  
    // HTTP request/response logging
    logRequest(req: {
      method?: string;
      url?: string;
      headers?: Record<string, any>;
      body?: any;
      query?: Record<string, any>;
      params?: Record<string, any>;
    }): void {
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
  
    logResponse(res: {
      statusCode?: number;
      headers?: Record<string, any>;
      body?: any;
      duration?: number;
    }): void {
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
  
    // Database operation logging
    logQuery(query: {
      sql?: string;
      params?: any[];
      duration?: number;
      table?: string;
      operation?: string;
    }): void {
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
  
    // Business logic logging
    logUserAction(userId: string, action: string, resource?: string, meta?: Record<string, any>): void {
      this.info('User Action', {
        user: {
          id: userId,
          action,
          resource,
        },
        ...meta,
      });
    }
  
    logSecurityEvent(event: {
      type: string;
      severity: 'low' | 'medium' | 'high' | 'critical';
      userId?: string;
      ip?: string;
      userAgent?: string;
      details?: Record<string, any>;
    }): void {
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
  
    // Create child logger with additional context
    child(context: string, meta?: Record<string, any>): Logger {
      const childContext = this.config.context ? `${this.config.context}:${context}` : context;
      const childLogger = new Logger(childContext, this.config);
      
      if (meta) {
        // Override the log method to include meta in all logs
        const originalLog = childLogger.log.bind(childLogger);
        childLogger.log = (level: LogLevel, levelName: string, message: string, logMeta?: Record<string, any>, error?: Error) => {
          const combinedMeta = { ...meta, ...logMeta };
          originalLog(level, levelName, message, combinedMeta, error);
        };
      }
      
      return childLogger;
    }
  
    // Correlation ID tracking
    setCorrelationId(correlationId: string): void {
      process.env.CORRELATION_ID = correlationId;
    }
  
    getCorrelationId(): string | undefined {
      return process.env.CORRELATION_ID;
    }
  
    // Lambda-specific logging
    logLambdaStart(event: any, context: any): void {
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
  
    logLambdaEnd(duration: number, memory?: number): void {
      this.info('Lambda Invocation End', {
        lambda: {
          duration,
          memory,
        },
      });
    }
  
    private getEventType(event: any): string {
      if (event.httpMethod) return 'API Gateway';
      if (event.Records) {
        if (event.Records[0]?.eventSource === 'aws:s3') return 'S3';
        if (event.Records[0]?.EventSource === 'aws:sns') return 'SNS';
        if (event.Records[0]?.eventSource === 'aws:sqs') return 'SQS';
        if (event.Records[0]?.eventSource === 'aws:dynamodb') return 'DynamoDB';
      }
      if (event.source === 'aws.events') return 'EventBridge';
      return 'Unknown';
    }
  }
  
  // Create default logger instance
  export const logger = new Logger('LambdaApp');
  
  // Export logger class for custom instances
  export { Logger };
  
  // Utility function to create contextual loggers
  export const createLogger = (context: string, config?: Partial<LoggerConfig>): Logger => {
    return new Logger(context, config);
  };
  
  // Performance decorator for automatic timing
  export function logPerformance(label?: string) {
    return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
      const originalMethod = descriptor.value;
      const perfLabel = label || `${target.constructor.name}.${propertyKey}`;
  
      descriptor.value = async function (...args: any[]) {
        logger.startTimer(perfLabel);
        try {
          const result = await originalMethod.apply(this, args);
          logger.endTimer(perfLabel);
          return result;
        } catch (error) {
          logger.endTimer(perfLabel);
          throw error;
        }
      };
  
      return descriptor;
    };
  }
  
  // Error logging utility
  export const logError = (error: Error, context?: string, meta?: Record<string, any>): void => {
    const contextLogger = context ? logger.child(context) : logger;
    contextLogger.error(error.message, error);
    
    if (meta) {
      contextLogger.debug('Error context', meta);
    }
  };
  
  // Lambda wrapper with automatic logging
  export const withLogging = (handler: any) => {
    return async (event: any, context: any) => {
      const requestLogger = logger.child('Handler', { requestId: context.awsRequestId });
      const startTime = Date.now();
  
      requestLogger.logLambdaStart(event, context);
      
      try {
        const result = await handler(event, context);
        const duration = Date.now() - startTime;
        
        requestLogger.logLambdaEnd(duration);
        return result;
      } catch (error) {
        const duration = Date.now() - startTime;
        
        requestLogger.error('Lambda execution failed', error as Error);
        requestLogger.logLambdaEnd(duration);
        throw error;
      }
    };
  };