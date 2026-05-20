const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); 
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// -------------------------------------------------------------------------
// MIDDLEWARE CONFIGURATION
// -------------------------------------------------------------------------
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://mediqueue-brown.vercel.app' 
    ], 
    credentials: true
}));
app.use(express.json());

// -------------------------------------------------------------------------
// MONGODB CONFIGURATION & LAZY CONNECTION POOLING
// -------------------------------------------------------------------------
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.8fclsxk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Global collection pointers accessible by all routes
let tutorCollection, bookingCollection, userCollection;
let dbInstance = null;

// Clean, lazy database loading method to keep serverless functions from hanging
async function getDB() {
    try {
        if (dbInstance) return dbInstance;
        
        // CRITICAL FIX: Explicitly await connection setup to prevent MongoServerSelectionError
        await client.connect();
        dbInstance = client.db("mediQueueDB");
        console.log("🚀 Serverless connection established cleanly with MongoDB Atlas!");
        return dbInstance;
    } catch (error) {
        console.error("❌ Database connection error:", error);
        throw error;
    }
}

// -------------------------------------------------------------------------
// BASE API ENDPOINTS & CONNECTIONS
// -------------------------------------------------------------------------

// Root health check route placed FIRST so Vercel can run instantly without hanging
app.get('/', (req, res) => {
    res.send('MediQueue Server is running beautifully.');
});

// Middleware to dynamically inject collections into active contexts safely
app.use(async (req, res, next) => {
    try {
        const db = await getDB();
        tutorCollection = db.collection("tutors");
        bookingCollection = db.collection("bookings");
        userCollection = db.collection("users");
        next();
    } catch (err) {
        console.error("❌ Middleware connection resolution error:", err);
        res.status(500).send({ 
            error: true, 
            message: "Database connectivity handshake timed out. Please refresh." 
        });
    }
});

// Custom JWT Verification Middleware
const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'Unauthorized access token missing' });
    }
    
    const token = authorization.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ error: true, message: 'Forbidden token access expired or invalid' });
        }
        req.decoded = decoded; 
        next();
    });
};

// -------------------------------------------------------------------------
// AUTHENTICATION & CUSTOM JWT ENDPOINTS
// -------------------------------------------------------------------------

app.post('/register', async (req, res) => {
    try {
        const { name, email, photo, password } = req.body;
        
        if (!userCollection) {
            return res.status(500).send({ error: true, message: "Database collections not initialized yet." });
        }

        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ error: true, message: "An account with this email already exists." });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = { name, email, photo, password: hashedPassword };
        const result = await userCollection.insertOne(newUser);
        res.send({ success: true, insertedId: result.insertedId });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send({ error: true, message: "Server error during registration workflow." });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
            return res.status(401).send({ error: true, message: "Incorrect email or password combination." });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).send({ error: true, message: "Incorrect email or password combination." });
        }
        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.send({
            success: true,
            token,
            user: { name: user.name, email: user.email, photo: user.photo }
        });
    } catch (error) {
        res.status(500).send({ error: true, message: "Server error during login authentication processing." });
    }
});

app.post('/jwt', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).send({ error: true, message: "Email parameter is required." });
        }
        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.send({ success: true, token });
    } catch (error) {
        res.status(500).send({ error: true, message: "JWT generation failed on server." });
    }
});

// -------------------------------------------------------------------------
// TUTORS ENDPOINTS
// -------------------------------------------------------------------------

app.get('/tutors/home', async (req, res) => {
    const query = {};
    const result = await tutorCollection.find(query).limit(6).toArray();
    res.send(result);
});

app.get('/tutors', async (req, res) => {
    const { search, startDate, endDate } = req.query;
    let query = {};

    if (search) {
        query.name = { $regex: search, $options: 'i' };
    }

    if (startDate || endDate) {
        query.sessionStartDate = {};
        if (startDate) query.sessionStartDate.$gte = startDate;
        if (endDate) query.sessionStartDate.$lte = endDate;
    }

    const result = await tutorCollection.find(query).toArray();
    res.send(result);
});

app.get('/tutors/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await tutorCollection.findOne(query);
        if (!result) {
            return res.status(404).send({ error: true, message: "Tutor entry not found." });
        }
        res.send(result);
    } catch (error) {
        res.status(500).send({ error: true, message: "Database lookup failure." });
    }
});

app.post('/tutors', verifyJWT, async (req, res) => {
    const newTutor = req.body;
    if (newTutor.totalSlot) newTutor.totalSlot = parseInt(newTutor.totalSlot);
    if (newTutor.hourlyFee) newTutor.hourlyFee = parseFloat(newTutor.hourlyFee);
    const result = await tutorCollection.insertOne(newTutor);
    res.send(result);
});

app.get('/my-tutors', verifyJWT, async (req, res) => {
    const email = req.query.email;
    if (req.decoded.email !== email) {
        return res.status(403).send({ error: true, message: 'Forbidden access management context' });
    }
    const query = { createdBy: email };
    const result = await tutorCollection.find(query).toArray();
    res.send(result);
});

app.put('/tutors/:id', verifyJWT, async (req, res) => {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updatedData = req.body;
    
    const updateDoc = {
        $set: {
            name: updatedData.name,
            image: updatedData.image,
            subject: updatedData.subject,
            availability: updatedData.availability,
            hourlyFee: parseFloat(updatedData.hourlyFee),
            totalSlot: parseInt(updatedData.totalSlot),
            sessionStartDate: updatedData.sessionStartDate,
            institution: updatedData.institution,
            experience: updatedData.experience,
            location: updatedData.location,
            teachingMode: updatedData.teachingMode,
        },
    };
    const result = await tutorCollection.updateOne(filter, updateDoc);
    res.send(result);
});

app.delete('/tutors/:id', verifyJWT, async (req, res) => {
    const id = req.params.id;
    const query = { _id: new ObjectId(id) };
    const result = await tutorCollection.deleteOne(query);
    res.send(result);
});

// -------------------------------------------------------------------------
// BOOKINGS ENDPOINTS
// -------------------------------------------------------------------------

app.post('/bookings', verifyJWT, async (req, res) => {
    const bookingData = req.body;
    const { tutorId } = bookingData;

    const tutor = await tutorCollection.findOne({ _id: new ObjectId(tutorId) });
    if (!tutor) {
        return res.status(404).send({ error: true, message: "Tutor entry could not be found." });
    }

    const currentDate = new Date();
    const sessionStartDate = new Date(tutor.sessionStartDate);
    if (currentDate < sessionStartDate) {
        return res.status(400).send({ error: true, message: "Booking is not available yet for this tutor." });
    }

    if (tutor.totalSlot <= 0) {
        return res.status(400).send({ error: true, message: "This session is fully booked. You can’t join at the moment." });
    }

    const bookingResult = await bookingCollection.insertOne(bookingData);
    const updateResult = await tutorCollection.updateOne(
        { _id: new ObjectId(tutorId) },
        { $inc: { totalSlot: -1 } }
    );
    res.send({ success: true, bookingResult, updateResult });
});

app.get('/my-bookings', verifyJWT, async (req, res) => {
    const email = req.query.email;
    if (req.decoded.email !== email) {
        return res.status(403).send({ error: true, message: 'Forbidden data extraction request' });
    }
    const query = { studentEmail: email };
    const result = await bookingCollection.find(query).toArray();
    res.send(result);
});

app.patch('/bookings/:id/cancel', verifyJWT, async (req, res) => {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = { $set: { status: 'cancelled' } };
    const result = await bookingCollection.updateOne(filter, updateDoc);
    res.send(result);
});

app.delete('/bookings/:id', verifyJWT, async (req, res) => {
    try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await bookingCollection.deleteOne(query);
        if (result.deletedCount === 1) {
            res.send({ success: true, message: "Booking cancelled successfully." });
        } else {
            res.status(404).send({ error: true, message: "Booking record not found." });
        }
    } catch (error) {
        res.status(500).send({ error: true, message: "Server error during cancellation workflow." });
    }
});

// -------------------------------------------------------------------------
// LIFECYCLE METHOD EXPORTS FOR PRODUCTION SERVERLESS HANDLER
// -------------------------------------------------------------------------
module.exports = app;

if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`Server executing seamlessly on port ${port}`);
    });
}