export class AppError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export function badRequest(message: string, code?: string) {
  return new AppError(400, message, code);
}

export function unauthorized(message = 'احراز هویت نامعتبر است') {
  return new AppError(401, message, 'UNAUTHORIZED');
}

export function forbidden(message = 'دسترسی غیرمجاز') {
  return new AppError(403, message, 'FORBIDDEN');
}

export function notFound(message = 'یافت نشد') {
  return new AppError(404, message, 'NOT_FOUND');
}

export function conflict(message: string) {
  return new AppError(409, message, 'CONFLICT');
}
