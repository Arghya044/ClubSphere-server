# ClubSphere Server

## 📌 Project Purpose

**ClubSphere Server** is the backend API for ClubSphere, a comprehensive club management platform that enables users to discover, join, and manage clubs and events. This RESTful API provides robust authentication, role-based access control, payment processing, and complete CRUD operations for clubs, events, memberships, and user management.

## 🌐 Live URL

> **API Base URL:** `https://club-sphere-server-arghya.vercel.app`  


## ✨ Key Features

### 🔐 Authentication & Authorization
- Firebase Authentication integration for secure user authentication
- JWT token-based verification middleware
- Role-based access control (Admin, Club Manager, Member)
- Automatic super admin creation on server startup

### 👥 User Management
- User registration and profile management
- Role assignment and updates (Admin only)
- Automatic user creation for new Firebase users
- User listing and retrieval

### 🏢 Club Management
- Create, read, update clubs
- Club approval workflow (pending → approved/rejected)
- Search and filter clubs by category, name
- Sort clubs by date and membership fee
- Manager-specific club retrieval
- Club status management (Admin only)

### 🎉 Event Management
- Create, read, update, and delete events
- Event registration system
- Paid and free event support
- Maximum attendee limits
- Event search and sorting
- Club-specific event listings

### 💳 Payment Processing
- Stripe integration for secure payments
- Membership fee payments
- Event ticket payments
- Payment intent creation
- Checkout session management
- Payment confirmation and tracking
- Payment history for users and admins

### 📊 Admin Dashboard
- Comprehensive statistics (users, clubs, events, payments)
- Club approval/rejection management
- All payments overview
- User role management

### 🎫 Membership System
- Join clubs with automatic status management
- Pending payment support
- Active membership tracking
- Member listing for club managers
- Membership history for users

### 📝 Event Registration
- Register for events with payment support
- Registration status tracking (registered, pending_payment)
- Registration history for users
- Attendee management for club managers

## 📦 Important NPM Packages Used

### Core Dependencies
- **`express`** (^4.18.2) - Fast, minimalist web framework for Node.js
- **`mongodb`** (^6.3.0) - Official MongoDB driver for database operations
- **`firebase-admin`** (^12.0.0) - Firebase Admin SDK for authentication and user management
- **`stripe`** (^14.14.0) - Payment processing integration
- **`cors`** (^2.8.5) - Enable Cross-Origin Resource Sharing
- **`dotenv`** (^16.4.5) - Environment variable management

### Development Dependencies
- **`nodemon`** (^3.0.3) - Auto-restart server during development

## 🚀 Getting Started

### Prerequisites
- Node.js (v14 or higher)
- MongoDB database
- Firebase project with Admin SDK credentials
- Stripe account for payment processing

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ClubSphere-server.git
cd ClubSphere-server
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory:
```env
PORT=5000
MONGODB_URI=your_mongodb_connection_string
DB_NAME=clubsphere

# Firebase Admin SDK
FIREBASE_PROJECT_ID=your_firebase_project_id
FIREBASE_PRIVATE_KEY=your_firebase_private_key
FIREBASE_CLIENT_EMAIL=your_firebase_client_email

# Super Admin
SUPER_ADMIN_EMAIL=admin@example.com

# Stripe
STRIPE_SECRET_KEY=your_stripe_secret_key
```

4. Start the development server:
```bash
npm run dev
```

5. For production:
```bash
npm start
```

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user

### Users
- `GET /api/users/me` - Get current user profile
- `GET /api/users` - Get all users (Admin only)
- `PATCH /api/users/:email/role` - Update user role (Admin only)

### Clubs
- `GET /api/clubs` - Get all approved clubs (with search, filter, sort)
- `GET /api/clubs/:id` - Get club by ID
- `POST /api/clubs` - Create new club (Club Manager only)
- `PUT /api/clubs/:id` - Update club (Club Manager only)
- `GET /api/clubs/manager/:email` - Get clubs by manager

### Events
- `GET /api/events` - Get all events (with search, sort)
- `GET /api/events/:id` - Get event by ID
- `POST /api/events` - Create event (Club Manager only)
- `PUT /api/events/:id` - Update event (Club Manager only)
- `DELETE /api/events/:id` - Delete event (Club Manager only)
- `GET /api/events/club/:clubId` - Get events by club

### Memberships
- `POST /api/memberships/join` - Join a club
- `GET /api/memberships/my-memberships` - Get user's memberships
- `GET /api/memberships/:id` - Get membership by ID
- `GET /api/memberships/club/:clubId/members` - Get club members (Manager only)

### Event Registrations
- `POST /api/event-registrations/register` - Register for event
- `GET /api/event-registrations/my-registrations` - Get user's registrations
- `GET /api/event-registrations/:id` - Get registration by ID
- `GET /api/event-registrations/event/:eventId` - Get event attendees (Manager only)

### Payments
- `POST /api/payments/create-payment-intent` - Create payment intent
- `POST /api/payments/create-membership-checkout-session` - Create membership checkout
- `POST /api/payments/create-event-checkout-session` - Create event checkout
- `POST /api/payments/confirm-checkout` - Confirm checkout payment
- `POST /api/payments/save-payment` - Save payment record
- `GET /api/payments/my-payments` - Get user's payment history
- `GET /api/payments/all` - Get all payments (Admin only)

### Admin
- `GET /api/admin/stats` - Get platform statistics (Admin only)
- `GET /api/admin/clubs` - Get all clubs with status filter (Admin only)
- `PATCH /api/admin/clubs/:id/status` - Approve/reject club (Admin only)

## 🔒 Security Features

- Firebase JWT token verification
- Role-based middleware protection
- Input validation and sanitization
- Secure payment processing with Stripe
- Environment variable protection
- CORS configuration

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB
- **Authentication:** Firebase Admin SDK
- **Payment:** Stripe
- **Deployment:** Vercel-ready


