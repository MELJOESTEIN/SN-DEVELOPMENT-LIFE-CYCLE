# MongoDB Database Security Countermeasures

## 1. Exposed Database Credentials
**Threat**: Database connection string with plaintext credentials is stored in the `.env` file and exposed in logs.

**Countermeasures**:
1. **Use Environment Variables Properly**:
   ```javascript
   // In .env file
   DB_USER=username
   DB_PASSWORD=password
   DB_HOST=host.mongodb.net
   DB_NAME=database
   
   // In code
   const connectionString = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/${process.env.DB_NAME}`;
   ```

2. **Implement Secure Logging**:
   ```javascript
   // Instead of this
   console.log("Connecting to MongoDB with connection string:", connectionString);
   
   // Do this
   console.log("Connecting to MongoDB database:", process.env.DB_NAME);
   ```

3. **Use MongoDB Atlas IAM Authentication**:
   ```javascript
   const { MongoClient } = require('mongodb');
   const { AWS } = require('aws-sdk');
   
   const generateAuthToken = async () => {
     const sts = new AWS.STS();
     const credentials = await sts.getSessionToken().promise();
     // Generate MongoDB auth token using AWS credentials
     return authToken;
   };
   
   const connectToMongoDB = async () => {
     const authToken = await generateAuthToken();
     const client = new MongoClient(uri, {
       auth: { mechanism: 'MONGODB-AWS', token: authToken }
     });
     await client.connect();
     return client;
   };
   ```

4. **Implement Credential Rotation**:
   - Create a script to rotate database credentials periodically
   - Use a secrets management service like AWS Secrets Manager or HashiCorp Vault

## 2. Insufficient Input Validation
**Threat**: Lack of comprehensive input validation before database operations.

**Countermeasures**:
1. **Implement Schema Validation**:
   ```javascript
   const UserSchema = db.Schema({
     email: {
       type: String,
       required: true,
       unique: true,
       match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
     },
     password: {
       type: String,
       required: true,
       minlength: [8, "Password must be at least 8 characters"],
       validate: {
         validator: function(v) {
           return /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$/.test(v);
         },
         message: "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character"
       }
     }
     // Other fields...
   });
   ```

2. **Sanitize Inputs**:
   ```javascript
   const sanitize = require('mongo-sanitize');
   
   exports.userSelect = (req, res) => {
     try {
       const sanitizedUsername = sanitize(req.query.username);
       UserModel.findOne({username: sanitizedUsername}, (err, user) => {
         // Process result
       });
     } catch (err) {
       return responses.error(res, err);
     }
   };
   ```

3. **Use Express Validator**:
   ```javascript
   const { body, validationResult } = require('express-validator');
   
   app.post('/register', [
     body('email').isEmail().normalizeEmail(),
     body('password').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/),
     body('username').isAlphanumeric().trim().escape()
   ], (req, res) => {
     const errors = validationResult(req);
     if (!errors.isEmpty()) {
       return res.status(400).json({ errors: errors.array() });
     }
     // Process valid request
   });
   ```

4. **Validate Array Fields**:
   ```javascript
   const UserSchema = db.Schema({
     // Other fields...
     articles: [{
       type: mongoose.Schema.Types.ObjectId,
       ref: 'Article',
       validate: {
         validator: async function(id) {
           const article = await mongoose.model('Article').findById(id);
           return article !== null;
         },
         message: 'Article does not exist'
       }
     }],
     cryptos: [{
       type: mongoose.Schema.Types.ObjectId,
       ref: 'Crypto',
       validate: {
         validator: async function(id) {
           const crypto = await mongoose.model('Crypto').findById(id);
           return crypto !== null;
         },
         message: 'Crypto does not exist'
       }
     }]
   });
   ```

## 3. Inadequate Access Controls
**Threat**: Role-based access control implementation has weaknesses.

**Countermeasures**:
1. **Implement Role-Based Middleware**:
   ```javascript
   // auth.js
   exports.requireAdmin = (req, res, next) => {
     if (!req.data || req.data.role !== 'admin') {
       return res.status(403).json({ message: 'Forbidden: Admin access required' });
     }
     next();
   };
   
   exports.requireSameUserOrAdmin = (req, res, next) => {
     if (!req.data || (req.data.id !== req.params.id && req.data.role !== 'admin')) {
       return res.status(403).json({ message: 'Forbidden: Unauthorized access' });
     }
     next();
   };
   
   // routes.js
   router.get('/users', auth.auth_jwt, auth.requireAdmin, userController.userList);
   router.put('/users/:id', auth.auth_jwt, auth.requireSameUserOrAdmin, userController.userUpdate);
   ```

2. **Implement Fine-Grained Permissions**:
   ```javascript
   const UserSchema = db.Schema({
     // Other fields...
     role: {
       type: String,
       required: true,
       enum: ['admin', 'editor', 'viewer', 'user']
     },
     permissions: [{
       type: String,
       enum: ['read:users', 'write:users', 'delete:users', 'read:articles', 'write:articles', 'delete:articles']
     }]
   });
   
   exports.hasPermission = (permission) => {
     return (req, res, next) => {
       if (!req.data || !req.data.permissions || !req.data.permissions.includes(permission)) {
         return res.status(403).json({ message: `Forbidden: ${permission} permission required` });
       }
       next();
     };
   };
   ```

3. **Implement Access Control Lists (ACL)**:
   ```javascript
   const acl = require('express-acl');
   
   // Configure ACL
   acl.config({
     baseUrl: '/',
     filename: 'acl.json',
     roleSearchPath: 'data.role'
   });
   
   // Apply ACL middleware after authentication
   app.use(auth.auth_jwt);
   app.use(acl.authorize);
   
   // acl.json
   [
     {
       "group": "admin",
       "permissions": [
         {
           "resource": "*",
           "methods": "*",
           "action": "allow"
         }
       ]
     },
     {
       "group": "user",
       "permissions": [
         {
           "resource": "users/:id",
           "methods": ["GET", "PUT"],
           "action": "allow",
           "condition": "req.params.id === req.data.id"
         },
         {
           "resource": "articles",
           "methods": ["GET"],
           "action": "allow"
         }
       ]
     }
   ]
   ```

## 4. Weak Password Policies
**Threat**: Minimal password requirements and handling.

**Countermeasures**:
1. **Implement Strong Password Policy**:
   ```javascript
   const passwordValidator = require('password-validator');
   
   const passwordSchema = new passwordValidator();
   passwordSchema
     .is().min(10)                // Minimum length 10
     .is().max(100)               // Maximum length 100
     .has().uppercase()           // Must have uppercase letters
     .has().lowercase()           // Must have lowercase letters
     .has().digits(2)             // Must have at least 2 digits
     .has().symbols(1)            // Must have at least 1 symbol
     .has().not().spaces()        // Should not have spaces
     .is().not().oneOf(['Password123', 'Passw0rd']); // Blacklist common passwords
   
   exports.validatePassword = (req, res, next) => {
     const validationResult = passwordSchema.validate(req.body.password, { list: true });
     if (validationResult.length > 0) {
       return res.status(400).json({ 
         message: 'Password does not meet requirements',
         issues: validationResult
       });
     }
     next();
   };
   ```

2. **Implement Password Expiration**:
   ```javascript
   const UserSchema = db.Schema({
     // Other fields...
     password: {
       type: String,
       required: true
     },
     passwordUpdatedAt: {
       type: Date,
       default: Date.now
     }
   });
   
   exports.checkPasswordExpiration = (req, res, next) => {
     const MAX_PASSWORD_AGE = 90 * 24 * 60 * 60 * 1000; // 90 days in milliseconds
     const passwordAge = Date.now() - req.user.passwordUpdatedAt;
     
     if (passwordAge > MAX_PASSWORD_AGE) {
       return res.status(403).json({
         message: 'Password expired. Please update your password.'
       });
     }
     next();
   };
   ```

3. **Implement Password History**:
   ```javascript
   const UserSchema = db.Schema({
     // Other fields...
     passwordHistory: [{
       password: String,
       createdAt: {
         type: Date,
         default: Date.now
       }
     }]
   });
   
   exports.updatePassword = async (req, res) => {
     try {
       const user = await UserModel.findById(req.data.id);
       
       // Check if password is in history (last 5 passwords)
       const isPasswordReused = await Promise.all(
         user.passwordHistory.slice(-5).map(async (historyItem) => {
           return await bcrypt.compare(req.body.newPassword, historyItem.password);
         })
       ).then(results => results.some(result => result));
       
       if (isPasswordReused) {
         return res.status(400).json({
           message: 'Cannot reuse one of your last 5 passwords'
         });
       }
       
       // Hash new password
       const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
       
       // Update user
       user.passwordHistory.push({ password: user.password });
       user.password = hashedPassword;
       user.passwordUpdatedAt = Date.now();
       await user.save();
       
       return res.status(200).json({
         message: 'Password updated successfully'
       });
     } catch (err) {
       return res.status(500).json({ error: err.message });
     }
   };
   ```

## 5. Insecure JWT Implementation
**Threat**: JWT implementation has security weaknesses.

**Countermeasures**:
1. **Add Token Expiration**:
   ```javascript
   exports.gen_jwt_token = function(data) {
     return jwt.sign(
       data,
       process.env.TOKEN_SECRET,
       { expiresIn: '1h' } // Token expires in 1 hour
     );
   };
   ```

2. **Implement Refresh Token Mechanism**:
   ```javascript
   // Generate tokens
   exports.generateTokens = function(data) {
     const accessToken = jwt.sign(
       data,
       process.env.ACCESS_TOKEN_SECRET,
       { expiresIn: '15m' }
     );
     
     const refreshToken = jwt.sign(
       { id: data.id },
       process.env.REFRESH_TOKEN_SECRET,
       { expiresIn: '7d' }
     );
     
     return { accessToken, refreshToken };
   };
   
   // Store refresh tokens
   const refreshTokens = new Map();
   
   exports.storeRefreshToken = function(userId, token) {
     refreshTokens.set(userId, token);
   };
   
   // Verify refresh token and generate new access token
   exports.refreshAccessToken = function(req, res) {
     const refreshToken = req.body.refreshToken;
     
     if (!refreshToken) {
       return res.status(401).json({ message: 'Refresh token required' });
     }
     
     try {
       const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
       
       // Check if refresh token is in our store
       const storedToken = refreshTokens.get(decoded.id);
       if (!storedToken || storedToken !== refreshToken) {
         return res.status(403).json({ message: 'Invalid refresh token' });
       }
       
       // Generate new access token
       const userData = { id: decoded.id, username: decoded.username, role: decoded.role };
       const accessToken = jwt.sign(
         userData,
         process.env.ACCESS_TOKEN_SECRET,
         { expiresIn: '15m' }
       );
       
       return res.status(200).json({ accessToken });
     } catch (err) {
       return res.status(403).json({ message: 'Invalid refresh token' });
     }
   };
   ```

3. **Use Asymmetric Key Signing**:
   ```javascript
   const fs = require('fs');
   const path = require('path');
   
   // Load private and public keys
   const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.key'), 'utf8');
   const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.key'), 'utf8');
   
   exports.gen_jwt_token = function(data) {
     return jwt.sign(
       data,
       privateKey,
       { 
         expiresIn: '1h',
         algorithm: 'RS256' // Use RSA SHA-256 instead of HMAC
       }
     );
   };
   
   exports.auth_jwt = function(req, res, next) {
     let auth_header = req.headers["authorization"];
     let token = auth_header && auth_header.split(" ")[1];
     
     jwt.verify(
       token,
       publicKey,
       { algorithms: ['RS256'] },
       (err, data) => {
         if (err) return res.sendStatus(401);
         req.data = data;
         next();
       }
     );
   };
   ```

## 6. Unprotected Sensitive Data
**Threat**: Sensitive user data lacks additional protection.

**Countermeasures**:
1. **Implement Field-Level Encryption**:
   ```javascript
   const crypto = require('crypto');
   
   // Encryption functions
   function encryptField(text) {
     const cipher = crypto.createCipheriv(
       process.env.CRYPTO_ALGO,
       Buffer.from(process.env.CRYPTO_KEY, 'base64'),
       Buffer.from(process.env.INIT_VECTOR, 'base64')
     );
     let encrypted = cipher.update(text, 'utf8', 'hex');
     encrypted += cipher.final('hex');
     return encrypted;
   }
   
   function decryptField(encryptedText) {
     const decipher = crypto.createDecipheriv(
       process.env.CRYPTO_ALGO,
       Buffer.from(process.env.CRYPTO_KEY, 'base64'),
       Buffer.from(process.env.INIT_VECTOR, 'base64')
     );
     let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
     decrypted += decipher.final('utf8');
     return decrypted;
   }
   
   // Mongoose schema with encryption
   const UserSchema = db.Schema({
     // Other fields...
     email: {
       type: String,
       required: true,
       unique: true,
       set: encryptField,
       get: decryptField
     },
     phoneNumber: {
       type: String,
       set: encryptField,
       get: decryptField
     }
   }, { toJSON: { getters: true }, toObject: { getters: true } });
   ```

2. **Use MongoDB Client-Side Field Level Encryption**:
   ```javascript
   const { MongoClient, ClientEncryption } = require('mongodb');
   const fs = require('fs');
   
   async function setupEncryption() {
     // Generate a local master key
     const localMasterKey = crypto.randomBytes(96);
     fs.writeFileSync('master-key.txt', localMasterKey);
     
     const kmsProviders = {
       local: {
         key: localMasterKey
       }
     };
     
     const keyVaultNamespace = 'encryption.__keyVault';
     
     const client = new MongoClient(process.env.DB_URI, {
       useNewUrlParser: true,
       useUnifiedTopology: true,
       autoEncryption: {
         keyVaultNamespace,
         kmsProviders,
         schemaMap: {
           'myDatabase.users': {
             bsonType: 'object',
             properties: {
               email: {
                 encrypt: {
                   bsonType: 'string',
                   algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
                 }
               },
               phoneNumber: {
                 encrypt: {
                   bsonType: 'string',
                   algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Random'
                 }
               }
             }
           }
         }
       }
     });
     
     return client;
   }
   ```

## 7. Lack of Database Activity Monitoring
**Threat**: No monitoring or logging of database access and operations.

**Countermeasures**:
1. **Enable MongoDB Auditing**:
   ```javascript
   // In mongod.conf
   auditLog:
     destination: file
     format: JSON
     path: /var/log/mongodb/audit.json
     filter: '{ atype: { $in: ["authenticate", "createCollection", "dropCollection", "createDatabase", "dropDatabase"] } }'
   ```

2. **Implement Application-Level Logging**:
   ```javascript
   const winston = require('winston');
   const MongoDB = require('winston-mongodb').MongoDB;
   
   // Create logger
   const logger = winston.createLogger({
     level: 'info',
     format: winston.format.combine(
       winston.format.timestamp(),
       winston.format.json()
     ),
     transports: [
       new winston.transports.File({ filename: 'error.log', level: 'error' }),
       new winston.transports.File({ filename: 'combined.log' }),
       new MongoDB({
         db: process.env.DB_URI,
         collection: 'logs',
         level: 'info',
         options: { useUnifiedTopology: true }
       })
     ]
   });
   
   // Middleware to log database operations
   exports.logDatabaseOperation = (operation) => {
     return (req, res, next) => {
       // Log before operation
       logger.info({
         operation,
         user: req.data ? req.data.username : 'anonymous',
         resource: req.originalUrl,
         method: req.method,
         ip: req.ip
       });
       
       next();
     };
   };
   
   // Use in routes
   router.post('/users', auth.auth_jwt, logDatabaseOperation('create_user'), userController.userCreate);
   ```

3. **Set Up Alerts for Suspicious Activities**:
   ```javascript
   const nodemailer = require('nodemailer');
   
   // Configure email transport
   const transporter = nodemailer.createTransport({
     service: 'gmail',
     auth: {
       user: process.env.ALERT_EMAIL,
       pass: process.env.ALERT_EMAIL_PASSWORD
     }
   });
   
   // Alert function
   function sendSecurityAlert(event) {
     const mailOptions = {
       from: process.env.ALERT_EMAIL,
       to: process.env.ADMIN_EMAIL,
       subject: `Security Alert: ${event.type}`,
       text: `
         Security Alert Details:
         Type: ${event.type}
         Time: ${event.timestamp}
         User: ${event.user}
         IP: ${event.ip}
         Details: ${event.details}
       `
     };
     
     transporter.sendMail(mailOptions);
   }
   
   // Example usage in login controller
   exports.login = (req, res) => {
     UserModel.findOne({email: req.body.email}).then(user => {
       if (!user) {
         // Log failed login attempt
         logger.warn({
           operation: 'login_attempt',
           email: req.body.email,
           success: false,
           reason: 'user_not_found',
           ip: req.ip
         });
         
         // Check for brute force attempts
         loginAttempts.increment(req.ip);
         if (loginAttempts.get(req.ip) > 5) {
           sendSecurityAlert({
             type: 'brute_force_attempt',
             timestamp: new Date(),
             user: req.body.email,
             ip: req.ip,
             details: `${loginAttempts.get(req.ip)} failed login attempts`
           });
         }
         
         return responses.unauthorized(res, "Invalid credentials");
       }
       
       // Continue with login process...
     });
   };
   ```

## 8. Unvalidated Schema Updates
**Threat**: Schema updates lack validation.

**Countermeasures**:
1. **Use Mongoose Middleware for Validation**:
   ```javascript
   const UserSchema = db.Schema({
     // Schema definition...
   });
   
   // Pre-save middleware
   UserSchema.pre('save', function(next) {
     // Validate entire document before saving
     const validationError = this.validateSync();
     if (validationError) {
       next(validationError);
     } else {
       next();
     }
   });
   
   // Pre-update middleware
   UserSchema.pre('findOneAndUpdate', function(next) {
     // Run validation on update operation
     this.options.runValidators = true;
     next();
   });
   ```

2. **Define Schemas for Array Elements**:
   ```javascript
   const ArticleSchema = db.Schema({
     title: {
       type: String,
       required: true
     },
     content: {
       type: String,
       required: true
     },
     author: {
       type: mongoose.Schema.Types.ObjectId,
       ref: 'User',
       required: true
     }
   });
   
   const UserSchema = db.Schema({
     // Other fields...
     articles: [{
       type: mongoose.Schema.Types.ObjectId,
       ref: 'Article'
     }]
   });
   
   // When adding an article to a user
   exports.articlesUpdate = (req, res) => {
     try {
       // First validate that article exists
       ArticleModel.findById(req.body.article, (err, article) => {
         if (err || !article) {
           return responses.notFound(res, "Article not found");
         }
         
         // Then update user
         UserModel.findById(req.params.id, function(err, foundUser) {
           // Update logic...
         });
       });
     } catch (err) {
       return responses.error(res, err);
     }
   };
   ```

## 9. Missing Database Connection Error Handling
**Threat**: Insufficient error handling for database connection failures.

**Countermeasures**:
1. **Implement Robust Connection Handling**:
   ```javascript
   const mongoose = require('mongoose');
   mongoose.set('strictQuery', true);
   
   // Connection options
   const options = {
     useNewUrlParser: true,
     useUnifiedTopology: true,
     serverSelectionTimeoutMS: 5000,
     socketTimeoutMS: 45000,
     connectTimeoutMS: 10000,
     maxPoolSize: 10,
     minPoolSize: 2
   };
   
   // Connection with retry logic
   const connectWithRetry = () => {
     console.log('MongoDB connection attempt...');
     mongoose.connect(process.env.DB_URI, options)
       .then(() => {
         console.log('MongoDB connected successfully');
       })
       .catch(err => {
         console.error('MongoDB connection error:', err);
         console.log('Retrying in 5 seconds...');
         setTimeout(connectWithRetry, 5000);
       });
   };
   
   // Initial connection
   connectWithRetry();
   
   // Handle connection events
   mongoose.connection.on('connected', () => {
     console.log('Mongoose connected to DB');
   });
   
   mongoose.connection.on('error', (err) => {
     console.error('Mongoose connection error:', err);
   });
   
   mongoose.connection.on('disconnected', () => {
     console.log('Mongoose disconnected');
     // Attempt to reconnect if disconnection was not intentional
     if (process.env.NODE_ENV !== 'test') {
       connectWithRetry();
     }
   });
   
   // Graceful shutdown
   process.on('SIGINT', async () => {
     await mongoose.connection.close();
     console.log('MongoDB connection closed due to app termination');
     process.exit(0);
   });
   
   exports.db_conn = mongoose;
   ```

2. **Implement Health Check Endpoint**:
   ```javascript
   app.get('/health', async (req, res) => {
     try {
       // Check database connection
       if (mongoose.connection.readyState !== 1) {
         return res.status(503).json({
           status: 'error',
           message: 'Database connection is not established',
           details: {
             readyState: mongoose.connection.readyState
           }
         });
       }
       
       // Try a simple database operation
       await mongoose.connection.db.admin().ping();
       
       return res.status(200).json({
         status: 'ok',
         message: 'Service is healthy',
         details: {
           database: 'connected',
           uptime: process.uptime()
         }
       });
     } catch (err) {
       return res.status(503).json({
         status: 'error',
         message: 'Service is unhealthy',
         details: {
           error: err.message
         }
       });
     }
   });
   ```

## Implementation Plan

### Immediate (1-2 weeks)
1. Secure database credentials
2. Implement input validation and sanitization
3. Add JWT token expiration
4. Enable basic logging

### Short-term (1-3 months)
1. Implement role-based access control
2. Set up field-level encryption
3. Improve password policies
4. Implement connection error handling

### Long-term (3-6 months)
1. Implement comprehensive monitoring
2. Set up alerting system
3. Migrate to more secure authentication methods
4. Conduct regular security audits
