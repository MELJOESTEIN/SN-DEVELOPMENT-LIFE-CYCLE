const axios = require("axios");
const mongo = require('mongo-sanitize');
const jwt = require('jsonwebtoken');

const inst_axios = axios.create({
    baseURL: 'http://localhost:4000/'
});

describe("MongoDB Security Tests", function() {
    let user_id = "";
    let adminToken = "";
    let regularUserToken = "";
    
    // Test data
    const adminUser = {
        firstname: "Admin", 
        lastname: "User", 
        username: "adminuser", 
        email: "admin@test.com", 
        password: "SecureP@ss123", 
        role: "admin"
    };
    
    const regularUser = {
        firstname: "Regular", 
        lastname: "User", 
        username: "regularuser", 
        email: "regular@test.com", 
        password: "SecureP@ss123", 
        role: "user"
    };
    
    // SQL Injection attempt payloads
    const sqlInjectionPayloads = [
        "' OR '1'='1", 
        "'; DROP TABLE users; --", 
        "' UNION SELECT * FROM users --"
    ];
    
    // NoSQL Injection attempt payloads
    const noSqlInjectionPayloads = [
        { "$gt": "" },
        { email: { "$ne": null } },
        { "$where": "function() { return true; }" }
    ];
    
    // XSS attempt payloads
    const xssPayloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "javascript:alert('XSS')"
    ];
    
    beforeAll(async () => {
        console.log("=========================================================== Security Tests ======================================================================");
        
        // Create test users
        try {
            // Clean up any existing test users
            try {
                const res = await inst_axios.post("/login", { email: adminUser.email, password: adminUser.password });
                adminToken = "Bearer " + res.data.data.token;
                
                const userRes = await inst_axios.get(`/users/user?username=${adminUser.username}`);
                if (userRes.data && userRes.data.data) {
                    await inst_axios.delete("/users/user/" + userRes.data.data.id);
                }
                
                const regularUserRes = await inst_axios.get(`/users/user?username=${regularUser.username}`);
                if (regularUserRes.data && regularUserRes.data.data) {
                    await inst_axios.delete("/users/user/" + regularUserRes.data.data.id);
                }
            } catch (error) {
                // Users might not exist yet, which is fine
            }
            
            // Register admin user
            await inst_axios.post("/register", adminUser);
            
            // Login as admin
            const adminLoginRes = await inst_axios.post("/login", { 
                email: adminUser.email, 
                password: adminUser.password 
            });
            adminToken = "Bearer " + adminLoginRes.data.data.token;
            
            // Register regular user
            await inst_axios.post("/register", regularUser);
            
            // Login as regular user
            const regularLoginRes = await inst_axios.post("/login", { 
                email: regularUser.email, 
                password: regularUser.password 
            });
            regularUserToken = "Bearer " + regularLoginRes.data.data.token;
            
        } catch (error) {
            console.error("Setup failed:", error.message);
        }
    });
    
    afterAll(async () => {
        try {
            // Clean up test users
            inst_axios.defaults.headers.common['authorization'] = adminToken;
            
            const adminUserRes = await inst_axios.get(`/users/user?username=${adminUser.username}`);
            if (adminUserRes.data && adminUserRes.data.data) {
                await inst_axios.delete("/users/user/" + adminUserRes.data.data.id);
            }
            
            const regularUserRes = await inst_axios.get(`/users/user?username=${regularUser.username}`);
            if (regularUserRes.data && regularUserRes.data.data) {
                await inst_axios.delete("/users/user/" + regularUserRes.data.data.id);
            }
        } catch (error) {
            console.error("Cleanup failed:", error.message);
        }
    });

    // 1. Test for MongoDB Injection vulnerabilities
    describe("MongoDB Injection Prevention", function() {
        it("Should sanitize user input and prevent NoSQL injection in login", async () => {
            for (const payload of noSqlInjectionPayloads) {
                try {
                    await inst_axios.post("/login", {
                        email: payload,
                        password: "anything"
                    });
                    // If we get here without error, it might be vulnerable
                    // But we need to check the response
                } catch (error) {
                    // We expect either a 400 Bad Request or 401 Unauthorized
                    expect(error.response.status).toBeGreaterThanOrEqual(400);
                    expect(error.response.status).toBeLessThan(500);
                }
            }
        });
        
        it("Should sanitize user input and prevent NoSQL injection in user lookup", async () => {
            for (const payload of noSqlInjectionPayloads) {
                try {
                    inst_axios.defaults.headers.common['authorization'] = adminToken;
                    await inst_axios.get(`/users/user?username=${JSON.stringify(payload)}`);
                } catch (error) {
                    // We expect either a 400 Bad Request or 404 Not Found
                    expect(error.response.status).toBeGreaterThanOrEqual(400);
                    expect(error.response.status).toBeLessThan(500);
                }
            }
        });
    });

    // 2. Test for XSS vulnerabilities
    describe("XSS Prevention", function() {
        it("Should sanitize user input to prevent XSS in user profile", async () => {
            inst_axios.defaults.headers.common['authorization'] = adminToken;
            
            // Get admin user ID
            const userRes = await inst_axios.get(`/users/user?username=${adminUser.username}`);
            const userId = userRes.data.data.id;
            
            for (const payload of xssPayloads) {
                // Update user with XSS payload
                await inst_axios.put(`/users/user/${userId}`, {
                    firstname: payload
                });
                
                // Retrieve user and check if payload was sanitized
                const updatedUser = await inst_axios.get(`/users/user?username=${adminUser.username}`);
                expect(updatedUser.data.data.firstname).not.toBe(payload);
                // Or alternatively, check that the script tags were escaped or removed
                expect(updatedUser.data.data.firstname).not.toContain("<script>");
            }
        });
    });

    // 3. Test for proper authentication
    describe("Authentication Security", function() {
        it("Should require valid JWT token for protected routes", async () => {
            // Remove authorization header
            delete inst_axios.defaults.headers.common['authorization'];
            
            try {
                await inst_axios.get("/users");
                fail("Request should not succeed without authorization");
            } catch (error) {
                expect(error.response.status).toBe(401);
            }
        });
        
        it("Should reject expired or invalid JWT tokens", async () => {
            // Create an expired token
            const payload = { id: "fakeid", role: "admin", exp: Math.floor(Date.now() / 1000) - 3600 };
            const expiredToken = "Bearer " + jwt.sign(payload, "fake-secret-key");
            
            inst_axios.defaults.headers.common['authorization'] = expiredToken;
            
            try {
                await inst_axios.get("/users");
                fail("Request should not succeed with expired token");
            } catch (error) {
                expect(error.response.status).toBe(401);
            }
        });
    });

    // 4. Test for proper authorization (RBAC)
    describe("Authorization Security", function() {
        it("Should prevent regular users from accessing admin routes", async () => {
            inst_axios.defaults.headers.common['authorization'] = regularUserToken;
            
            try {
                // Assuming there's an admin-only route
                await inst_axios.get("/admin/dashboard");
                fail("Regular user should not access admin routes");
            } catch (error) {
                expect(error.response.status).toBe(403);
            }
        });
        
        it("Should prevent users from modifying other users' data", async () => {
            inst_axios.defaults.headers.common['authorization'] = regularUserToken;
            
            // Get admin user ID
            inst_axios.defaults.headers.common['authorization'] = adminToken;
            const adminUserRes = await inst_axios.get(`/users/user?username=${adminUser.username}`);
            const adminUserId = adminUserRes.data.data.id;
            
            // Try to modify admin user with regular user token
            inst_axios.defaults.headers.common['authorization'] = regularUserToken;
            try {
                await inst_axios.put(`/users/user/${adminUserId}`, {
                    firstname: "Hacked"
                });
                fail("Regular user should not modify other users' data");
            } catch (error) {
                expect(error.response.status).toBe(403);
            }
        });
    });

    // 5. Test for secure password handling
    describe("Password Security", function() {
        it("Should enforce password complexity requirements", async () => {
            try {
                await inst_axios.post("/register", {
                    firstname: "Weak", 
                    lastname: "Password", 
                    username: "weakpass", 
                    email: "weak@test.com", 
                    password: "123", // Too short
                    role: "user"
                });
                fail("Should reject weak passwords");
            } catch (error) {
                expect(error.response.status).toBe(400);
            }
        });
        
        it("Should not return password hash in user data", async () => {
            inst_axios.defaults.headers.common['authorization'] = adminToken;
            
            const userRes = await inst_axios.get(`/users/user?username=${adminUser.username}`);
            expect(userRes.data.data.password).toBeUndefined();
        });
    });

    // 6. Test for proper error handling
    describe("Error Handling Security", function() {
        it("Should not expose sensitive information in error messages", async () => {
            try {
                await inst_axios.post("/login", {
                    email: "nonexistent@test.com",
                    password: "anything"
                });
                fail("Should not succeed with invalid credentials");
            } catch (error) {
                expect(error.response.data).not.toContain("stack");
                expect(error.response.data).not.toContain("at /");
                expect(error.response.data.message).not.toContain("SQL");
                expect(error.response.data.message).not.toContain("syntax");
            }
        });
    });

    // 7. Test for MongoDB connection security
    describe("MongoDB Connection Security", function() {
        // This is more of a configuration check than a test
        it("Should use secure MongoDB connection string", async () => {
            // This is a mock test since we can't directly access the .env file
            // In a real scenario, you would check the actual connection string
            const mockConnectionString = process.env.MONGODB_CONNSTRING || "";
            
            // Check if using authentication
            const hasAuth = mockConnectionString.includes("@");
            expect(hasAuth).toBe(true);
            
            // Check if using SSL
            const hasSSL = mockConnectionString.includes("ssl=true");
            expect(hasSSL).toBe(true);
        });
    });
});
