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
