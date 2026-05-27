/**
 * Base error class for all Attestix SDK errors.
 */
export class AttestixError extends Error {
	public readonly statusCode: number;
	public readonly detail: string;

	constructor(message: string, statusCode: number, detail?: string) {
		super(message);
		this.name = 'AttestixError';
		this.statusCode = statusCode;
		this.detail = detail ?? message;

		// Maintains proper stack trace in V8 environments
		const ErrorWithCapture = Error as typeof Error & {
			captureStackTrace?: (target: object, constructor: Function) => void;
		};
		if (ErrorWithCapture.captureStackTrace) {
			ErrorWithCapture.captureStackTrace(this, this.constructor);
		}
	}
}

/**
 * Thrown when the API returns a 401 Unauthorized response.
 * Indicates an invalid or missing API key.
 */
export class AttestixAuthError extends AttestixError {
	constructor(detail?: string) {
		super(
			detail ?? 'Authentication failed - check your API key',
			401,
			detail,
		);
		this.name = 'AttestixAuthError';
	}
}

/**
 * Thrown when the API returns a 404 Not Found response.
 * The requested resource does not exist.
 */
export class AttestixNotFoundError extends AttestixError {
	constructor(detail?: string) {
		super(
			detail ?? 'Resource not found',
			404,
			detail,
		);
		this.name = 'AttestixNotFoundError';
	}
}

/**
 * Thrown when the API returns a 400 Bad Request response.
 * The request parameters failed validation.
 */
export class AttestixValidationError extends AttestixError {
	constructor(detail?: string) {
		super(
			detail ?? 'Validation error - check your request parameters',
			400,
			detail,
		);
		this.name = 'AttestixValidationError';
	}
}

/**
 * Thrown when the API returns a 429 Too Many Requests response.
 * The client has exceeded the rate limit.
 */
export class AttestixRateLimitError extends AttestixError {
	public readonly retryAfter: number | null;

	constructor(detail?: string, retryAfter?: number) {
		super(
			detail ?? 'Rate limit exceeded - try again later',
			429,
			detail,
		);
		this.name = 'AttestixRateLimitError';
		this.retryAfter = retryAfter ?? null;
	}
}
