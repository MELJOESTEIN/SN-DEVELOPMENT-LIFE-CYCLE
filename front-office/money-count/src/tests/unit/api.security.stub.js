/**
 * API Security Testing Stubs
 * 
 * This file provides mock implementations of API endpoints for security testing.
 * It simulates both secure and insecure API behaviors to test frontend security handling.
 */

import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';

// Create a new instance of axios-mock-adapter
const mock = new MockAdapter(axios);

/**
 * Setup secure API stubs
 * These implement proper security practices
 */
export const setupSecureApiStubs = () => {
  // Reset any existing mocks
  mock.reset();
  
  // Secure login endpoint
  mock.onPost('/api/login').reply((config) => {
    const { email, password } = JSON.parse(config.data);
    
    // Validate input
    if (!email || !password) {
      return [400, { message: 'Email and password are required' }];
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return [400, { message: 'Invalid email format' }];
    }
    
    // Password strength validation
    if (password.length < 8) {
      return [400, { message: 'Password must be at least 8 characters' }];
    }
    
    // Simulate successful login
    if (email === 'admin@example.com' && password === 'StrongP@ss123') {
      return [200, {
        token: 'secure-jwt-token-with-proper-expiration',
        user: {
          id: '1',
          username: 'admin',
          email: 'admin@example.com',
          role: 'admin'
          // Note: No password hash is returned
        }
      }];
    }
    
    if (email === 'user@example.com' && password === 'UserP@ss123') {
      return [200, {
        token: 'secure-jwt-token-for-regular-user',
        user: {
          id: '2',
          username: 'user',
          email: 'user@example.com',
          role: 'user'
        }
      }];
    }
    
    // Invalid credentials
    return [401, { message: 'Invalid credentials' }];
  });
  
  // Secure user profile endpoint
  mock.onGet('/api/user/profile').reply((config) => {
    // Check for authorization header
    const authHeader = config.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return [401, { message: 'Unauthorized' }];
    }
    
    const token = authHeader.split(' ')[1];
    
    // Validate token (in a real app, you'd verify the JWT)
    if (token === 'secure-jwt-token-with-proper-expiration') {
      return [200, {
        id: '1',
        username: 'admin',
        email: 'admin@example.com',
        role: 'admin',
        bio: 'Admin user profile'
      }];
    }
    
    if (token === 'secure-jwt-token-for-regular-user') {
      return [200, {
        id: '2',
        username: 'user',
        email: 'user@example.com',
        role: 'user',
        bio: 'Regular user profile'
      }];
    }
    
    // Invalid token
    return [401, { message: 'Invalid token' }];
  });
  
  // Secure profile update endpoint
  mock.onPut('/api/user/profile').reply((config) => {
    // Check for authorization header
    const authHeader = config.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return [401, { message: 'Unauthorized' }];
    }
    
    const token = authHeader.split(' ')[1];
    const { bio } = JSON.parse(config.data);
    
    // Sanitize input (simulated)
    const sanitizedBio = bio
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    
    // Validate token
    if (token === 'secure-jwt-token-with-proper-expiration' || 
        token === 'secure-jwt-token-for-regular-user') {
      return [200, { 
        message: 'Profile updated successfully',
        bio: sanitizedBio
      }];
    }
    
    // Invalid token
    return [401, { message: 'Invalid token' }];
  });
  
  // Admin-only endpoint
  mock.onGet('/api/admin/dashboard').reply((config) => {
    // Check for authorization header
    const authHeader = config.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return [401, { message: 'Unauthorized' }];
    }
    
    const token = authHeader.split(' ')[1];
    
    // Only admin can access this endpoint
    if (token === 'secure-jwt-token-with-proper-expiration') {
      return [200, { 
        message: 'Admin dashboard data',
        stats: {
          users: 100,
          activeUsers: 75,
          newUsers: 10
        }
      }];
    }
    
    // Regular user - forbidden
    if (token === 'secure-jwt-token-for-regular-user') {
      return [403, { message: 'Forbidden: Admin access required' }];
    }
    
    // Invalid token
    return [401, { message: 'Invalid token' }];
  });
};

/**
 * Setup vulnerable API stubs
 * These implement insecure practices to test security handling
 */
export const setupVulnerableApiStubs = () => {
  // Reset any existing mocks
  mock.reset();
  
  // Vulnerable login endpoint
  mock.onPost('/api/login').reply((config) => {
    const { email, password } = JSON.parse(config.data);
    
    // No input validation
    
    // SQL Injection vulnerability simulation
    if (password.includes("' OR '1'='1")) {
      return [200, {
        token: 'insecure-jwt-token-without-expiration',
        user: {
          id: '1',
          username: 'admin',
          email: 'admin@example.com',
          role: 'admin',
          password: '$2a$10$hashed_password' // Leaking password hash
        }
      }];
    }
    
    // Simulate successful login
    if (email === 'admin@example.com' && password === 'admin123') {
      return [200, {
        token: 'insecure-jwt-token-without-expiration',
        user: {
          id: '1',
          username: 'admin',
          email: 'admin@example.com',
          role: 'admin',
          password: '$2a$10$hashed_password' // Leaking password hash
        }
      }];
    }
    
    // Verbose error message with stack trace
    return [401, { 
      message: 'Invalid credentials',
      error: 'Error: User not found in database query: SELECT * FROM users WHERE email = "' + email + '"',
      stack: 'at Object.login (/app/controllers/auth.js:25:13)\nat processTicksAndRejections (internal/process/task_queues.js:95:5)'
    }];
  });
  
  // Vulnerable user profile endpoint
  mock.onGet('/api/user/profile').reply((config) => {
    // No token validation
    return [200, {
      id: '1',
      username: 'admin',
      email: 'admin@example.com',
      role: 'admin',
      password: '$2a$10$hashed_password', // Leaking password hash
      bio: '<script>alert("XSS")</script>Admin user profile'
    }];
  });
  
  // Vulnerable profile update endpoint
  mock.onPut('/api/user/profile').reply((config) => {
    // No token validation
    const { bio } = JSON.parse(config.data);
    
    // No input sanitization
    return [200, { 
      message: 'Profile updated successfully',
      bio: bio // Unsanitized
    }];
  });
  
  // Vulnerable admin endpoint with no access control
  mock.onGet('/api/admin/dashboard').reply((config) => {
    // No access control
    return [200, { 
      message: 'Admin dashboard data',
      stats: {
        users: 100,
        activeUsers: 75,
        newUsers: 10
      },
      sensitiveData: {
        serverConfig: {
          dbConnectionString: 'mongodb://admin:password@localhost:27017/app',
          secretKey: 'super-secret-key-123'
        }
      }
    }];
  });
};

/**
 * Reset all API stubs
 */
export const resetApiStubs = () => {
  mock.reset();
  mock.restore();
};

/**
 * Setup mixed API stubs (some secure, some vulnerable)
 * Useful for testing partial security implementations
 */
export const setupMixedApiStubs = () => {
  // Reset any existing mocks
  mock.reset();
  
  // Secure login endpoint
  mock.onPost('/api/login').reply((config) => {
    const { email, password } = JSON.parse(config.data);
    
    // Validate input
    if (!email || !password) {
      return [400, { message: 'Email and password are required' }];
    }
    
    // Simulate successful login
    if (email === 'admin@example.com' && password === 'StrongP@ss123') {
      return [200, {
        token: 'secure-jwt-token-with-proper-expiration',
        user: {
          id: '1',
          username: 'admin',
          email: 'admin@example.com',
          role: 'admin'
        }
      }];
    }
    
    // Invalid credentials
    return [401, { message: 'Invalid credentials' }];
  });
  
  // Vulnerable user profile endpoint
  mock.onGet('/api/user/profile').reply((config) => {
    // Check for authorization header but don't validate token properly
    const authHeader = config.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return [401, { message: 'Unauthorized' }];
    }
    
    // Return data with XSS payload
    return [200, {
      id: '1',
      username: 'admin',
      email: 'admin@example.com',
      role: 'admin',
      bio: '<script>alert("XSS")</script>Admin user profile'
    }];
  });
  
  // Secure profile update endpoint
  mock.onPut('/api/user/profile').reply((config) => {
    // Check for authorization header
    const authHeader = config.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return [401, { message: 'Unauthorized' }];
    }
    
    const token = authHeader.split(' ')[1];
    const { bio } = JSON.parse(config.data);
    
    // Sanitize input
    const sanitizedBio = bio
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '');
    
    return [200, { 
      message: 'Profile updated successfully',
      bio: sanitizedBio
    }];
  });
  
  // Vulnerable admin endpoint with improper access control
  mock.onGet('/api/admin/dashboard').reply((config) => {
    // Check for authorization but don't validate role
    const authHeader = config.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return [401, { message: 'Unauthorized' }];
    }
    
    // Any authenticated user can access admin data
    return [200, { 
      message: 'Admin dashboard data',
      stats: {
        users: 100,
        activeUsers: 75,
        newUsers: 10
      }
    }];
  });
};
