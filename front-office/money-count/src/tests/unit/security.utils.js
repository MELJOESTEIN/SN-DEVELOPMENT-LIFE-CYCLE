/**
 * Security utility functions for testing
 */

// XSS payloads for testing input sanitization
export const xssPayloads = [
  "<script>alert('XSS')</script>",
  "<img src='x' onerror='alert(\"XSS\")'>",
  "javascript:alert('XSS')",
  "<div onmouseover='alert(1)'>Hover me</div>",
  "<svg/onload=alert('XSS')>",
  "'-alert(1)-'"
];

// CSRF tokens for testing
export const generateMockCSRFToken = () => {
  return 'mock-csrf-token-' + Math.random().toString(36).substring(2, 15);
};

// JWT token utilities
export const generateMockJWT = (payload, expired = false) => {
  // Mock JWT structure (header.payload.signature)
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  
  // If expired, set exp to a past time
  if (expired) {
    payload.exp = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
  } else {
    payload.exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  }
  
  const encodedPayload = btoa(JSON.stringify(payload));
  const signature = 'mock_signature'; // In real tests, you'd use a proper signing method
  
  return `${header}.${encodedPayload}.${signature}`;
};

// Mock vulnerable data for testing sanitization
export const vulnerableInputs = {
  sqlInjection: [
    "' OR '1'='1", 
    "'; DROP TABLE users; --", 
    "' UNION SELECT * FROM users --"
  ],
  commandInjection: [
    "user; rm -rf /",
    "user && cat /etc/passwd",
    "user | cat /etc/shadow"
  ],
  pathTraversal: [
    "../../../etc/passwd",
    "..\\..\\..\\Windows\\system.ini",
    "/etc/passwd%00"
  ]
};

// Security headers checker
export const requiredSecurityHeaders = [
  'Content-Security-Policy',
  'X-Content-Type-Options',
  'X-Frame-Options',
  'X-XSS-Protection',
  'Strict-Transport-Security'
];

// Check if a string contains potentially dangerous HTML
export const containsUnsafeHTML = (str) => {
  const unsafePatterns = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /on\w+\s*=/gi,
    /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
    /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi,
    /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi
  ];
  
  return unsafePatterns.some(pattern => pattern.test(str));
};
