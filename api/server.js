const express = require('express');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Connect to MongoDB
mongoose.connect('mongodb://db:27017/jwt-lab', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define user schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

// Initialize admin user
async function initializeAdminUser() {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('adminpassword', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        role: 'admin'
      });
      console.log('Admin user created');
    }
  } catch (error) {
    console.error('Error creating admin user:', error);
  }

  try {
    const userExists = await User.findOne({ username: 'user' });
    if (!userExists) {
      const hashedPassword = await bcrypt.hash('userpassword', 10);
      await User.create({
        username: 'user',
        password: hashedPassword,
        role: 'user'
      });
      console.log('Regular user created');
    }
  } catch (error) {
    console.error('Error creating regular user:', error);
  }
}

// Routes
app.get('/', (req, res) => {
  res.send('JWT Vulnerability Lab API');
});

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }
    
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'Username already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      password: hashedPassword,
      role: 'user'
    });
    
    res.status(201).json({ message: 'User registered successfully', userId: user._id });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login endpoint - VULNERABILITY 1: Weak signature verification
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    const payload = {
      userId: user._id,
      username: user.username,
      role: user.role
    };
    
    // VULNERABILITY: Using weak secret key
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// VULNERABILITY 2: Accepts 'none' algorithm
app.get('/api/none-alg', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    // VULNERABILITY: Accepting 'none' algorithm
    let decoded;
    try {
      // First attempt normal verification
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      // If that fails, check if it's using 'none' algorithm
      const parts = token.split('.');
      if (parts.length === 3) {
        const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
        if (header.alg === 'none') {
          // VULNERABILITY: Accept tokens with 'none' algorithm
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
          decoded = payload;
        } else {
          throw err;
        }
      } else {
        throw err;
      }
    }
    
    res.json({ 
      message: 'Protected resource accessed', 
      user: decoded 
    });
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// VULNERABILITY 3: Algorithm confusion attack
app.get('/api/alg-confusion', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    // VULNERABILITY: Not checking which algorithm is used
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'RS256', 'none'] });
    
    res.json({ 
      message: 'Protected resource accessed with algorithm confusion', 
      user: decoded 
    });
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// VULNERABILITY 4: Missing signature validation
app.get('/api/missing-validation', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    // VULNERABILITY: Not properly validating the token
    const parts = token.split('.');
    if (parts.length >= 2) {
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      
      // VULNERABILITY: Just trusting the payload without verification
      res.json({ 
        message: 'Accessed without proper verification', 
        user: payload 
      });
    } else {
      throw new Error('Invalid token format');
    }
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// VULNERABILITY 5: JWT secret disclosure
app.get('/api/debug', (req, res) => {
  // VULNERABILITY: Exposing JWT secret in error logs and responses
  const debugInfo = {
    environment: process.env,
    config: {
      jwtSecret: JWT_SECRET
    },
    serverInfo: {
      platform: process.platform,
      nodeVersion: process.version
    }
  };
  
  console.log('Debug info requested:', debugInfo);
  res.json(debugInfo);
});

// Normal, secure endpoint (for comparison)
app.get('/api/secure', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    
    // Secure way: specify algorithm and use a strong secret
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    
    res.json({ 
      message: 'Protected resource accessed securely', 
      user: decoded 
    });
  } catch (error) {
    console.error('Auth error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Protected admin route
app.get('/api/admin', (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    if (decoded.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied: Admin role required' });
    }
    
    res.json({ 
      message: 'Admin area accessed', 
      secretData: 'This is a secret admin message'
    });
  } catch (error) {
    console.error('Admin auth error:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Start server
app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  await initializeAdminUser();
}); 