const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const stripe = require('stripe');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Client
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let db;

// Firebase Admin Setup
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Stripe Setup
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);

// Connect to MongoDB and Create Super Admin
async function connectDB() {
  try {
    await client.connect();
    db = client.db(process.env.DB_NAME);
    console.log("✅ Connected to MongoDB successfully!");
    await createSuperAdmin();
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    process.exit(1);
  }
}

async function createSuperAdmin() {
  try {
    const usersCollection = db.collection('users');
    const superAdminEmail = process.env.SUPER_ADMIN_EMAIL;
    const existingSuperAdmin = await usersCollection.findOne({ email: superAdminEmail });
    
    if (!existingSuperAdmin) {
      await usersCollection.insertOne({
        name: "Super Admin",
        email: superAdminEmail,
        role: "admin",
        photoURL: "https://i.ibb.co/2yfvQvz/admin-avatar.png",
        createdAt: new Date()
      });
      console.log("✅ Super Admin created successfully!");
    } else {
      console.log("ℹ️ Super Admin already exists");
    }
  } catch (error) {
    console.error("❌ Error creating super admin:", error);
  }
}
// Middleware: Verify Firebase Token
async function verifyToken(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}
// Middleware: Check Role
function checkRole(...allowedRoles) {
  return async (req, res, next) => {
    try {
      const usersCollection = db.collection('users');
      const user = await usersCollection.findOne({ email: req.user.email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      if (!allowedRoles.includes(user.role)) {
        return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
      }
      req.userRole = user.role;
      next();
    } catch (error) {
      console.error('Role check error:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  };
}
// Helper Functions
function isValidObjectId(id) {
  return ObjectId.isValid(id);
}

function createObjectId(id) {
  return new ObjectId(id);
}

// Root Route
app.get('/', (req, res) => {
  res.json({ message: 'ClubSphere API is running!' });
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, photoURL } = req.body;
    if (!name || !email) {
      return res.status(400).json({ message: 'Name and email are required' });
    }
    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(200).json({ message: 'User already exists', user: existingUser });
    }
    const newUser = {
      name,
      email,
      photoURL: photoURL || '',
      role: 'member',
      createdAt: new Date()
    };
    const result = await usersCollection.insertOne(newUser);
    res.status(201).json({ message: 'User registered successfully', userId: result.insertedId });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});