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

// ==================== MONGODB CONNECTION CACHING (Serverless Optimized) ====================
const uri = process.env.MONGODB_URI;
let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
    maxPoolSize: 10,
    minPoolSize: 1,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 10000,
    connectTimeoutMS: 5000,
  });

  try {
    await client.connect();
    const db = client.db(process.env.DB_NAME);
    cachedClient = client;
    cachedDb = db;
    
    // Initialize indexes (non-blocking)
    initializeIndexes(db).catch(err => console.error('Index initialization error:', err));
    
    console.log("✅ Connected to MongoDB successfully!");
    return { client, db };
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    throw error;
  }
}

// Initialize database indexes
async function initializeIndexes(db) {
  try {
    // Users indexes
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    
    // Clubs indexes
    await db.collection('clubs').createIndex({ status: 1 });
    await db.collection('clubs').createIndex({ managerEmail: 1 });
    await db.collection('clubs').createIndex({ category: 1 });
    
    // Memberships indexes
    await db.collection('memberships').createIndex({ userEmail: 1 });
    await db.collection('memberships').createIndex({ clubId: 1 });
    await db.collection('memberships').createIndex({ userEmail: 1, clubId: 1 });
    
    // Event Registrations indexes
    await db.collection('eventRegistrations').createIndex({ userEmail: 1 });
    await db.collection('eventRegistrations').createIndex({ eventId: 1 });
    await db.collection('eventRegistrations').createIndex({ userEmail: 1, eventId: 1 });
    
    // Payments indexes
    await db.collection('payments').createIndex({ userEmail: 1 });
    await db.collection('payments').createIndex({ stripePaymentIntentId: 1 }, { unique: true });
    
    // Events indexes
    await db.collection('events').createIndex({ clubId: 1 });
    
    console.log("✅ Database indexes initialized");
  } catch (error) {
    console.error("❌ Index initialization error:", error);
  }
}

// Get database instance (for serverless)
async function getDb() {
  const { db } = await connectToDatabase();
  return db;
}

// ==================== FIREBASE ADMIN SETUP (Cached) ====================
let firebaseAdminInitialized = false;

function getFirebaseAdmin() {
  if (!firebaseAdminInitialized) {
    const serviceAccount = {
      type: "service_account",
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
    };

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    firebaseAdminInitialized = true;
  }
  return admin;
}

// ==================== STRIPE SETUP (With Timeout) ====================
const stripeClient = stripe(process.env.STRIPE_SECRET_KEY, {
  timeout: 8000,
  maxNetworkRetries: 2,
});

// Stripe timeout wrapper
function withStripeTimeout(promise, timeoutMs = 8000) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Stripe request timeout')), timeoutMs)
    )
  ]);
}

// ==================== CREATE SUPER ADMIN (Non-blocking) ====================
async function createSuperAdmin() {
  try {
    const db = await getDb();
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

// Initialize super admin non-blocking
if (process.env.SUPER_ADMIN_EMAIL) {
  createSuperAdmin().catch(err => console.error('Super admin creation error:', err));
}

// ==================== MIDDLEWARE: VERIFY FIREBASE TOKEN (Optimized) ====================
async function verifyToken(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const admin = getFirebaseAdmin();
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    
    // Fetch user from DB and attach to req.user (optimize for checkRole)
    try {
      const db = await getDb();
      const usersCollection = db.collection('users');
      const user = await usersCollection.findOne(
        { email: decodedToken.email },
        { projection: { email: 1, role: 1, name: 1, photoURL: 1 } }
      );
      if (user) {
        req.user.dbUser = user;
        req.userRole = user.role;
      }
    } catch (error) {
      console.error('User fetch error in verifyToken:', error);
    }
    
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// ==================== MIDDLEWARE: CHECK ROLE (Optimized - uses cached user) ====================
function checkRole(...allowedRoles) {
  return async (req, res, next) => {
    try {
      // Use cached user data from verifyToken if available
      if (req.user.dbUser) {
        const user = req.user.dbUser;
        if (!allowedRoles.includes(user.role)) {
          return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
        }
        req.userRole = user.role;
        return next();
      }
      
      // Fallback: fetch from DB if not cached
      const db = await getDb();
      const usersCollection = db.collection('users');
      const user = await usersCollection.findOne(
        { email: req.user.email },
        { projection: { email: 1, role: 1 } }
      );
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      if (!allowedRoles.includes(user.role)) {
        return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
      }
      req.userRole = user.role;
      req.user.dbUser = user;
      next();
    } catch (error) {
      console.error('Role check error:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
  };
}

// ==================== HELPER FUNCTIONS ====================
function isValidObjectId(id) {
  return ObjectId.isValid(id);
}

function createObjectId(id) {
  return new ObjectId(id);
}

// ==================== ROOT ROUTE ====================
app.get('/', (req, res) => {
  res.json({ message: 'ClubSphere API is running!' });
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, photoURL } = req.body;
    
    // Early validation
    if (!name || !email) {
      return res.status(400).json({ message: 'Name and email are required' });
    }
    
    const db = await getDb();
    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne(
      { email },
      { projection: { email: 1, name: 1, role: 1, photoURL: 1, createdAt: 1 } }
    );
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

// ==================== USER ROUTES ====================

app.get('/api/users/me', verifyToken, async (req, res) => {
  try {
    const db = await getDb();
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne(
      { email: req.user.email },
      { projection: { email: 1, name: 1, role: 1, photoURL: 1, createdAt: 1 } }
    );
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/users', verifyToken, checkRole('admin'), async (req, res) => {
  try {
    const db = await getDb();
    const usersCollection = db.collection('users');
    const users = await usersCollection.find({}).toArray();
    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.patch('/api/users/:email/role', verifyToken, checkRole('admin'), async (req, res) => {
  try {
    const { email } = req.params;
    const { role } = req.body;
    
    // Early validation
    if (!['admin', 'clubManager', 'member'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }
    if (email === req.user.email) {
      return res.status(403).json({ message: 'Cannot change your own role' });
    }
    
    const db = await getDb();
    const usersCollection = db.collection('users');
    const result = await usersCollection.updateOne(
      { email },
      { $set: { role, updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    console.error('Update role error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== CLUB ROUTES ====================

app.get('/api/clubs', async (req, res) => {
  try {
    const { search, category, sort } = req.query;
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    let query = { status: 'approved' };
    if (search) {
      query.clubName = { $regex: search, $options: 'i' };
    }
    if (category) {
      query.category = category;
    }
    let sortOption = {};
    if (sort === 'newest') {
      sortOption = { createdAt: -1 };
    } else if (sort === 'oldest') {
      sortOption = { createdAt: 1 };
    } else if (sort === 'highestFee') {
      sortOption = { membershipFee: -1 };
    } else if (sort === 'lowestFee') {
      sortOption = { membershipFee: 1 };
    }
    const clubs = await clubsCollection.find(query).sort(sortOption).toArray();
    
    // Add cache headers
    res.set('Cache-Control', 'public, max-age=60');
    res.json(clubs);
  } catch (error) {
    console.error('Get clubs error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/clubs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(id) });
    if (!club) {
      return res.status(404).json({ message: 'Club not found' });
    }
    res.json(club);
  } catch (error) {
    console.error('Get club error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/clubs', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { clubName, description, category, location, bannerImage, membershipFee } = req.body;
    
    // Early validation
    if (!clubName || !description || !category || !location) {
      return res.status(400).json({ message: 'All required fields must be provided' });
    }
    
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const newClub = {
      clubName,
      description,
      category,
      location,
      bannerImage: bannerImage || '',
      membershipFee: parseFloat(membershipFee) || 0,
      status: 'pending',
      managerEmail: req.user.email,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    const result = await clubsCollection.insertOne(newClub);
    res.status(201).json({ message: 'Club created successfully. Waiting for admin approval.', clubId: result.insertedId });
  } catch (error) {
    console.error('Create club error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/clubs/:id', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(id) });
    if (!club) {
      return res.status(404).json({ message: 'Club not found' });
    }
    if (club.managerEmail !== req.user.email) {
      return res.status(403).json({ message: 'You can only update your own clubs' });
    }
    const { clubName, description, category, location, bannerImage, membershipFee } = req.body;
    const updateData = {
      clubName: clubName || club.clubName,
      description: description || club.description,
      category: category || club.category,
      location: location || club.location,
      bannerImage: bannerImage || club.bannerImage,
      membershipFee: membershipFee !== undefined ? parseFloat(membershipFee) : club.membershipFee,
      updatedAt: new Date()
    };
    await clubsCollection.updateOne({ _id: createObjectId(id) }, { $set: updateData });
    res.json({ message: 'Club updated successfully' });
  } catch (error) {
    console.error('Update club error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/clubs/manager/:email', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { email } = req.params;
    if (email !== req.user.email) {
      return res.status(403).json({ message: 'Access denied' });
    }
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const clubs = await clubsCollection.find({ managerEmail: email }).toArray();
    res.json(clubs);
  } catch (error) {
    console.error('Get manager clubs error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== EVENT ROUTES ====================

app.get('/api/events', async (req, res) => {
  try {
    const { search, sort } = req.query;
    const db = await getDb();
    const eventsCollection = db.collection('events');
    let query = {};
    if (search) {
      query.title = { $regex: search, $options: 'i' };
    }
    let sortOption = {};
    if (sort === 'newest') {
      sortOption = { createdAt: -1 };
    } else if (sort === 'oldest') {
      sortOption = { createdAt: 1 };
    } else if (sort === 'upcoming') {
      sortOption = { eventDate: 1 };
    }
    const events = await eventsCollection.find(query).sort(sortOption).toArray();
    
    // Add cache headers
    res.set('Cache-Control', 'public, max-age=60');
    res.json(events);
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }
    const db = await getDb();
    const eventsCollection = db.collection('events');
    const event = await eventsCollection.findOne({ _id: createObjectId(id) });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.json(event);
  } catch (error) {
    console.error('Get event error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/events', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { clubId, title, description, eventDate, location, isPaid, eventFee, maxAttendees } = req.body;
    
    // Early validation
    if (!clubId || !title || !description || !eventDate || !location) {
      return res.status(400).json({ message: 'All required fields must be provided' });
    }
    if (!isValidObjectId(clubId)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }
    
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(clubId) });
    if (!club) {
      return res.status(404).json({ message: 'Club not found' });
    }
    if (club.managerEmail !== req.user.email) {
      return res.status(403).json({ message: 'You can only create events for your own clubs' });
    }
    const eventsCollection = db.collection('events');
    const newEvent = {
      clubId,
      title,
      description,
      eventDate: new Date(eventDate),
      location,
      isPaid: isPaid || false,
      eventFee: isPaid ? parseFloat(eventFee) || 0 : 0,
      maxAttendees: maxAttendees ? parseInt(maxAttendees) : null,
      createdAt: new Date()
    };
    const result = await eventsCollection.insertOne(newEvent);
    res.status(201).json({ message: 'Event created successfully', eventId: result.insertedId });
  } catch (error) {
    console.error('Create event error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/events/:id', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }
    const db = await getDb();
    const eventsCollection = db.collection('events');
    const event = await eventsCollection.findOne({ _id: createObjectId(id) });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(event.clubId) });
    if (!club || club.managerEmail !== req.user.email) {
      return res.status(403).json({ message: 'You can only update events for your own clubs' });
    }
    const { title, description, eventDate, location, isPaid, eventFee, maxAttendees } = req.body;
    const updateData = {
      title: title || event.title,
      description: description || event.description,
      eventDate: eventDate ? new Date(eventDate) : event.eventDate,
      location: location || event.location,
      isPaid: isPaid !== undefined ? isPaid : event.isPaid,
      eventFee: eventFee !== undefined ? parseFloat(eventFee) : event.eventFee,
      maxAttendees: maxAttendees !== undefined ? (maxAttendees ? parseInt(maxAttendees) : null) : event.maxAttendees,
      updatedAt: new Date()
    };
    await eventsCollection.updateOne({ _id: createObjectId(id) }, { $set: updateData });
    res.json({ message: 'Event updated successfully' });
  } catch (error) {
    console.error('Update event error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/api/events/:id', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }
    const db = await getDb();
    const eventsCollection = db.collection('events');
    const event = await eventsCollection.findOne({ _id: createObjectId(id) });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(event.clubId) });
    if (!club || club.managerEmail !== req.user.email) {
      return res.status(403).json({ message: 'You can only delete events for your own clubs' });
    }
    await eventsCollection.deleteOne({ _id: createObjectId(id) });
    res.json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Delete event error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/events/club/:clubId', async (req, res) => {
  try {
    const { clubId } = req.params;
    if (!isValidObjectId(clubId)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }
    const db = await getDb();
    const eventsCollection = db.collection('events');
    const events = await eventsCollection.find({ clubId }).toArray();
    res.json(events);
  } catch (error) {
    console.error('Get club events error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== MEMBERSHIP ROUTES ====================

app.post('/api/memberships/join', verifyToken, async (req, res) => {
  try {
    const { clubId, paymentId } = req.body;
    
    // Early validation
    if (!clubId) {
      return res.status(400).json({ message: 'Club ID is required' });
    }
    if (!isValidObjectId(clubId)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }

    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(clubId) });
    if (!club) {
      return res.status(404).json({ message: 'Club not found' });
    }
    if (club.status !== 'approved') {
      return res.status(400).json({ message: 'Club is not approved yet' });
    }

    const membershipsCollection = db.collection('memberships');
    const existingMembership = await membershipsCollection.findOne({
      userEmail: req.user.email,
      clubId,
    });

    if (existingMembership && existingMembership.status === 'active') {
      return res.status(400).json({ message: 'You are already a member of this club' });
    }

    // When payment is required but not yet completed, keep membership pending so the user can pay later.
    const requiresPayment = club.membershipFee > 0;
    const isImmediateActivation = !requiresPayment || Boolean(paymentId);
    const status = isImmediateActivation ? 'active' : 'pending_payment';

    if (existingMembership) {
      // Update existing pending membership if payment just completed
      const updateFields = {
        status,
        paymentId: paymentId || existingMembership.paymentId || null,
        updatedAt: new Date(),
      };
      await membershipsCollection.updateOne(
        { _id: existingMembership._id },
        { $set: updateFields }
      );
      return res.status(200).json({
        message: status === 'active'
          ? 'Membership activated successfully'
          : 'Added to dashboard, pay if required',
        membershipId: existingMembership._id,
      });
    }

    const newMembership = {
      userEmail: req.user.email,
      clubId,
      status,
      paymentId: paymentId || null,
      joinedAt: new Date(),
      updatedAt: new Date(),
      expiresAt: null,
    };
    const result = await membershipsCollection.insertOne(newMembership);

    return res.status(201).json({
      message: status === 'active'
        ? 'Membership activated successfully'
        : 'Added to dashboard, pay if required',
      membershipId: result.insertedId,
    });
  } catch (error) {
    console.error('Join club error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/memberships/my-memberships', verifyToken, async (req, res) => {
  try {
    const db = await getDb();
    const membershipsCollection = db.collection('memberships');
    
    // Use aggregation with $lookup to replace N+1 queries
    const membershipsWithClubs = await membershipsCollection.aggregate([
      { $match: { userEmail: req.user.email } },
      {
        $addFields: {
          clubIdObjectId: {
            $convert: {
              input: '$clubId',
              to: 'objectId',
              onError: null,
              onNull: null
            }
          }
        }
      },
      {
        $lookup: {
          from: 'clubs',
          localField: 'clubIdObjectId',
          foreignField: '_id',
          as: 'club'
        }
      },
      {
        $unwind: {
          path: '$club',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          clubIdObjectId: 0
        }
      }
    ]).toArray();
    
    res.json(membershipsWithClubs);
  } catch (error) {
    console.error('Get memberships error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/memberships/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid membership ID' });
    }
    const db = await getDb();
    const membershipsCollection = db.collection('memberships');
    const clubsCollection = db.collection('clubs');
    const membership = await membershipsCollection.findOne({ _id: createObjectId(id) });
    if (!membership || membership.userEmail !== req.user.email) {
      return res.status(404).json({ message: 'Membership not found' });
    }
    const club = await clubsCollection.findOne({ _id: createObjectId(membership.clubId) });
    res.json({ ...membership, club });
  } catch (error) {
    console.error('Get membership error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/memberships/club/:clubId/members', verifyToken, async (req, res) => {
  try {
    const { clubId } = req.params;
    if (!isValidObjectId(clubId)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(clubId) });
    if (!club) {
      return res.status(404).json({ message: 'Club not found' });
    }
    if (club.managerEmail !== req.user.email) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const membershipsCollection = db.collection('memberships');
    
    // Use aggregation with $lookup to replace N+1 queries
    const membersWithDetails = await membershipsCollection.aggregate([
      { $match: { clubId } },
      {
        $lookup: {
          from: 'users',
          localField: 'userEmail',
          foreignField: 'email',
          as: 'user'
        }
      },
      {
        $unwind: {
          path: '$user',
          preserveNullAndEmptyArrays: true
        }
      }
    ]).toArray();
    
    res.json(membersWithDetails);
  } catch (error) {
    console.error('Get club members error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== PAYMENT ROUTES ====================

app.post('/api/payments/create-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount, clubId, clubName } = req.body;
    
    // Early validation
    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid amount' });
    }
    
    const paymentIntent = await withStripeTimeout(
      stripeClient.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: 'usd',
        metadata: {
          userEmail: req.user.email,
          clubId,
          clubName,
          type: 'membership'
        }
      })
    );
    res.json({ clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id });
  } catch (error) {
    console.error('Create payment intent error:', error);
    res.status(500).json({ message: 'Payment failed' });
  }
});

app.post('/api/payments/create-membership-checkout-session', verifyToken, async (req, res) => {
  try {
    const { clubId, membershipId, successUrl, cancelUrl } = req.body;
    
    // Early validation
    if (!clubId || !successUrl || !cancelUrl) {
      return res.status(400).json({ message: 'Club ID, successUrl and cancelUrl are required' });
    }
    if (!isValidObjectId(clubId)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }

    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const membershipsCollection = db.collection('memberships');

    const club = await clubsCollection.findOne({ _id: createObjectId(clubId) });
    if (!club) {
      return res.status(404).json({ message: 'Club not found' });
    }
    if (club.membershipFee <= 0) {
      return res.status(400).json({ message: 'No payment required for this club' });
    }

    if (membershipId && !isValidObjectId(membershipId)) {
      return res.status(400).json({ message: 'Invalid membership ID' });
    }

    const membership = membershipId
      ? await membershipsCollection.findOne({ _id: createObjectId(membershipId) })
      : await membershipsCollection.findOne({ clubId, userEmail: req.user.email });

    if (!membership || membership.userEmail !== req.user.email) {
      return res.status(404).json({ message: 'Membership not found for user' });
    }

    const session = await withStripeTimeout(
      stripeClient.checkout.sessions.create({
        mode: 'payment',
        customer_email: req.user.email,
        payment_method_types: ['card'],
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: `${club.clubName} Membership` },
              unit_amount: Math.round(club.membershipFee * 100),
            },
            quantity: 1,
          },
        ],
        success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}&type=membership`,
        cancel_url: `${cancelUrl}?type=membership`,
        metadata: {
          type: 'membership',
          clubId,
          membershipId: membership._id.toString(),
          userEmail: req.user.email,
        },
      })
    );

    res.json({ url: session.url, sessionId: session.id });
  } catch (error) {
    console.error('Create checkout session error:', error);
    res.status(500).json({ message: 'Failed to start checkout' });
  }
});

app.post('/api/payments/create-event-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount, eventId, eventTitle } = req.body;
    
    // Early validation
    if (!amount || amount <= 0) {
      return res.status(400).json({ message: 'Invalid amount' });
    }
    
    const paymentIntent = await withStripeTimeout(
      stripeClient.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: 'usd',
        metadata: {
          userEmail: req.user.email,
          eventId,
          eventTitle,
          type: 'event'
        }
      })
    );
    res.json({ clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id });
  } catch (error) {
    console.error('Create event payment intent error:', error);
    res.status(500).json({ message: 'Payment failed' });
  }
});

app.post('/api/payments/create-event-checkout-session', verifyToken, async (req, res) => {
  try {
    const { eventId, registrationId, successUrl, cancelUrl } = req.body;
    
    // Early validation
    if (!eventId || !successUrl || !cancelUrl) {
      return res.status(400).json({ message: 'Event ID, successUrl and cancelUrl are required' });
    }
    if (!isValidObjectId(eventId)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }

    const db = await getDb();
    const eventsCollection = db.collection('events');
    const registrationsCollection = db.collection('eventRegistrations');
    const event = await eventsCollection.findOne({ _id: createObjectId(eventId) });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    if (!event.isPaid || event.eventFee <= 0) {
      return res.status(400).json({ message: 'No payment required for this event' });
    }

    if (registrationId && !isValidObjectId(registrationId)) {
      return res.status(400).json({ message: 'Invalid registration ID' });
    }

    const registration = registrationId
      ? await registrationsCollection.findOne({ _id: createObjectId(registrationId) })
      : await registrationsCollection.findOne({ eventId, userEmail: req.user.email });

    if (!registration || registration.userEmail !== req.user.email) {
      return res.status(404).json({ message: 'Registration not found for user' });
    }

    const session = await withStripeTimeout(
      stripeClient.checkout.sessions.create({
        mode: 'payment',
        customer_email: req.user.email,
        payment_method_types: ['card'],
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: { name: `${event.title} Ticket` },
              unit_amount: Math.round(event.eventFee * 100),
            },
            quantity: 1,
          },
        ],
        success_url: `${successUrl}?session_id={CHECKOUT_SESSION_ID}&type=event`,
        cancel_url: `${cancelUrl}?type=event`,
        metadata: {
          type: 'event',
          eventId,
          registrationId: registration._id.toString(),
          userEmail: req.user.email,
        },
      })
    );

    res.json({ url: session.url, sessionId: session.id });
  } catch (error) {
    console.error('Create event checkout session error:', error);
    res.status(500).json({ message: 'Failed to start checkout' });
  }
});

app.post('/api/payments/save-payment', verifyToken, async (req, res) => {
  try {
    const { amount, type, clubId, eventId, stripePaymentIntentId } = req.body;
    
    // Early validation
    if (!amount || !stripePaymentIntentId) {
      return res.status(400).json({ message: 'Amount and stripePaymentIntentId are required' });
    }
    
    const db = await getDb();
    const paymentsCollection = db.collection('payments');
    const payment = {
      userEmail: req.user.email,
      amount: parseFloat(amount),
      type,
      clubId: clubId || null,
      eventId: eventId || null,
      stripePaymentIntentId,
      status: 'completed',
      createdAt: new Date()
    };
    const result = await paymentsCollection.insertOne(payment);
    res.status(201).json({ message: 'Payment recorded successfully', paymentId: result.insertedId });
  } catch (error) {
    console.error('Save payment error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/payments/confirm-checkout', verifyToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    // Early validation
    if (!sessionId) {
      return res.status(400).json({ message: 'sessionId is required' });
    }

    const session = await withStripeTimeout(
      stripeClient.checkout.sessions.retrieve(sessionId)
    );
    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }
    if (session.payment_status !== 'paid') {
      return res.status(400).json({ message: 'Payment not completed' });
    }
    if (session.metadata?.userEmail !== req.user.email) {
      return res.status(403).json({ message: 'This session does not belong to the user' });
    }

    const stripePaymentIntentId = session.payment_intent;
    const amount = session.amount_total ? session.amount_total / 100 : 0;
    const type = session.metadata?.type;

    const db = await getDb();
    const paymentsCollection = db.collection('payments');
    const membershipsCollection = db.collection('memberships');
    const registrationsCollection = db.collection('eventRegistrations');

    const existingPayment = await paymentsCollection.findOne({ stripePaymentIntentId });
    if (!existingPayment) {
      await paymentsCollection.insertOne({
        userEmail: req.user.email,
        amount,
        type,
        clubId: session.metadata?.clubId || null,
        eventId: session.metadata?.eventId || null,
        stripePaymentIntentId,
        status: 'completed',
        createdAt: new Date(),
      });
    }

    if (type === 'membership') {
      const { clubId, membershipId } = session.metadata;
      const membershipFilter = membershipId && isValidObjectId(membershipId)
        ? { _id: createObjectId(membershipId) }
        : { clubId, userEmail: req.user.email };

      const updateResult = await membershipsCollection.updateOne(
        membershipFilter,
        {
          $set: {
            status: 'active',
            paymentId: stripePaymentIntentId,
            updatedAt: new Date(),
          },
        },
        { upsert: true }
      );

      // If we upserted because membership was missing, ensure required fields
      if (updateResult.upsertedCount > 0) {
        await membershipsCollection.updateOne(
          { _id: updateResult.upsertedId },
          {
            $setOnInsert: {
              userEmail: req.user.email,
              clubId,
              joinedAt: new Date(),
              expiresAt: null,
            },
          }
        );
      }

      return res.json({ message: 'Membership payment confirmed' });
    }

    if (type === 'event') {
      const { eventId, registrationId } = session.metadata;
      const registrationFilter = registrationId && isValidObjectId(registrationId)
        ? { _id: createObjectId(registrationId) }
        : { eventId, userEmail: req.user.email };

      const updateResult = await registrationsCollection.updateOne(
        registrationFilter,
        {
          $set: {
            status: 'registered',
            paymentId: stripePaymentIntentId,
            updatedAt: new Date(),
          },
        },
        { upsert: true }
      );

      if (updateResult.upsertedCount > 0) {
        await registrationsCollection.updateOne(
          { _id: updateResult.upsertedId },
          {
            $setOnInsert: {
              eventId,
              userEmail: req.user.email,
              registeredAt: new Date(),
            },
          }
        );
      }

      return res.json({ message: 'Event payment confirmed' });
    }

    res.json({ message: 'Payment confirmed' });
  } catch (error) {
    console.error('Confirm checkout error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/payments/my-payments', verifyToken, async (req, res) => {
  try {
    const db = await getDb();
    const paymentsCollection = db.collection('payments');
    const payments = await paymentsCollection.find({ userEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(payments);
  } catch (error) {
    console.error('Get payments error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/payments/all', verifyToken, async (req, res) => {
  try {
    // Use cached user data from verifyToken
    if (!req.user.dbUser || req.user.dbUser.role !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const db = await getDb();
    const paymentsCollection = db.collection('payments');
    const payments = await paymentsCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json(payments);
  } catch (error) {
    console.error('Get all payments error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== ADMIN ROUTES ====================

app.get('/api/admin/stats', verifyToken, checkRole('admin'), async (req, res) => {
  try {
    const db = await getDb();
    const usersCollection = db.collection('users');
    const clubsCollection = db.collection('clubs');
    const membershipsCollection = db.collection('memberships');
    const eventsCollection = db.collection('events');
    const paymentsCollection = db.collection('payments');
    
    // Parallelize all count operations
    const [
      totalUsers,
      totalClubs,
      approvedClubs,
      pendingClubs,
      rejectedClubs,
      totalMemberships,
      totalEvents,
      payments
    ] = await Promise.all([
      usersCollection.countDocuments(),
      clubsCollection.countDocuments(),
      clubsCollection.countDocuments({ status: 'approved' }),
      clubsCollection.countDocuments({ status: 'pending' }),
      clubsCollection.countDocuments({ status: 'rejected' }),
      membershipsCollection.countDocuments(),
      eventsCollection.countDocuments(),
      paymentsCollection.find({}).toArray()
    ]);
    
    const totalPayments = payments.reduce((sum, payment) => sum + payment.amount, 0);
    
    res.json({
      totalUsers,
      totalClubs,
      approvedClubs,
      pendingClubs,
      rejectedClubs,
      totalMemberships,
      totalEvents,
      totalPayments: totalPayments.toFixed(2)
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/admin/clubs', verifyToken, checkRole('admin'), async (req, res) => {
  try {
    const { status } = req.query;
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    let query = {};
    if (status) {
      query.status = status;
    }
    const clubs = await clubsCollection.find(query).sort({ createdAt: -1 }).toArray();
    res.json(clubs);
  } catch (error) {
    console.error('Get clubs error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.patch('/api/admin/clubs/:id/status', verifyToken, checkRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    // Early validation
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid club ID' });
    }
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'Invalid status. Use approved or rejected' });
    }
    
    const db = await getDb();
    const clubsCollection = db.collection('clubs');
    const result = await clubsCollection.updateOne(
      { _id: createObjectId(id) },
      { $set: { status, updatedAt: new Date() } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ message: 'Club not found' });
    }
    res.json({ message: `Club ${status} successfully` });
  } catch (error) {
    console.error('Update club status error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== EVENT REGISTRATION ROUTES ====================

app.post('/api/event-registrations/register', verifyToken, async (req, res) => {
  try {
    const { eventId, clubId, paymentId } = req.body;
    
    // Early validation
    if (!eventId || !clubId) {
      return res.status(400).json({ message: 'Event ID and Club ID are required' });
    }
    if (!isValidObjectId(eventId)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }

    const db = await getDb();
    const eventsCollection = db.collection('events');
    const event = await eventsCollection.findOne({ _id: createObjectId(eventId) });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }

    const registrationsCollection = db.collection('eventRegistrations');
    const existingRegistration = await registrationsCollection.findOne({
      eventId,
      userEmail: req.user.email,
    });

    if (existingRegistration && existingRegistration.status === 'registered') {
      return res.status(400).json({ message: 'You are already registered for this event' });
    }

    const requiresPayment = event.isPaid;
    const isImmediateRegistration = !requiresPayment || Boolean(paymentId);
    const status = isImmediateRegistration ? 'registered' : 'pending_payment';

    if (existingRegistration) {
      await registrationsCollection.updateOne(
        { _id: existingRegistration._id },
        {
          $set: {
            status,
            paymentId: paymentId || existingRegistration.paymentId || null,
            updatedAt: new Date(),
          },
        }
      );
      return res.status(200).json({
        message: status === 'registered'
          ? 'Registration confirmed'
          : 'Added to dashboard, pay if required',
        registrationId: existingRegistration._id,
      });
    }

    const newRegistration = {
      eventId,
      userEmail: req.user.email,
      clubId,
      status,
      paymentId: paymentId || null,
      registeredAt: new Date(),
      updatedAt: new Date(),
    };
    const result = await registrationsCollection.insertOne(newRegistration);
    res.status(201).json({
      message: status === 'registered'
        ? 'Registration confirmed'
        : 'Added to dashboard, pay if required',
      registrationId: result.insertedId,
    });
  } catch (error) {
    console.error('Event registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/event-registrations/my-registrations', verifyToken, async (req, res) => {
  try {
    const db = await getDb();
    const eventRegistrationsCollection = db.collection('eventRegistrations');
    
    // Use aggregation with $lookup to replace N+1 queries
    const registrationsWithDetails = await eventRegistrationsCollection.aggregate([
      { $match: { userEmail: req.user.email } },
      {
        $addFields: {
          eventIdObjectId: {
            $convert: {
              input: '$eventId',
              to: 'objectId',
              onError: null,
              onNull: null
            }
          },
          clubIdObjectId: {
            $convert: {
              input: '$clubId',
              to: 'objectId',
              onError: null,
              onNull: null
            }
          }
        }
      },
      {
        $lookup: {
          from: 'events',
          localField: 'eventIdObjectId',
          foreignField: '_id',
          as: 'event'
        }
      },
      {
        $unwind: {
          path: '$event',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $lookup: {
          from: 'clubs',
          localField: 'clubIdObjectId',
          foreignField: '_id',
          as: 'club'
        }
      },
      {
        $unwind: {
          path: '$club',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          eventIdObjectId: 0,
          clubIdObjectId: 0
        }
      }
    ]).toArray();
    
    res.json(registrationsWithDetails);
  } catch (error) {
    console.error('Get registrations error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/event-registrations/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ message: 'Invalid registration ID' });
    }
    const db = await getDb();
    const registrationsCollection = db.collection('eventRegistrations');
    const eventsCollection = db.collection('events');
    const clubsCollection = db.collection('clubs');
    const registration = await registrationsCollection.findOne({ _id: createObjectId(id) });
    if (!registration || registration.userEmail !== req.user.email) {
      return res.status(404).json({ message: 'Registration not found' });
    }
    const event = await eventsCollection.findOne({ _id: createObjectId(registration.eventId) });
    const club = await clubsCollection.findOne({ _id: createObjectId(registration.clubId) });
    res.json({ ...registration, event, club });
  } catch (error) {
    console.error('Get registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/event-registrations/event/:eventId', verifyToken, checkRole('clubManager'), async (req, res) => {
  try {
    const { eventId } = req.params;
    if (!isValidObjectId(eventId)) {
      return res.status(400).json({ message: 'Invalid event ID' });
    }
    const db = await getDb();
    const eventsCollection = db.collection('events');
    const event = await eventsCollection.findOne({ _id: createObjectId(eventId) });
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    const clubsCollection = db.collection('clubs');
    const club = await clubsCollection.findOne({ _id: createObjectId(event.clubId) });
    if (!club || club.managerEmail !== req.user.email) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    const eventRegistrationsCollection = db.collection('eventRegistrations');
    
    // Use aggregation with $lookup to replace N+1 queries
    const registrationsWithUsers = await eventRegistrationsCollection.aggregate([
      { $match: { eventId } },
      {
        $lookup: {
          from: 'users',
          localField: 'userEmail',
          foreignField: 'email',
          as: 'user'
        }
      },
      {
        $unwind: {
          path: '$user',
          preserveNullAndEmptyArrays: true
        }
      }
    ]).toArray();
    
    res.json(registrationsWithUsers);
  } catch (error) {
    console.error('Get event registrations error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ==================== ERROR HANDLERS ====================
app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// ==================== START SERVER ====================
async function startServer() {
  try {
    // For Vercel serverless, we don't need to start a server
    // Connection will be established on first request
    if (process.env.VERCEL !== '1') {
      await connectToDatabase();
      app.listen(PORT, () => {
        console.log(`🚀 Server is running on port ${PORT}`);
      });
    }
  } catch (error) {
    console.error('Failed to start server:', error);
    if (process.env.VERCEL !== '1') {
      process.exit(1);
    }
  }
}

if (process.env.VERCEL !== '1') {
  startServer();
}

// Export for Vercel
module.exports = app;
