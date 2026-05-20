const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Safely handles password hashing
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://mediqueue-brown.vercel.app' // Added https:// prefix
    ], // <-- CRITICAL: Added missing comma right here!
    credentials: true
}));
app.use(express.json());

// MongoDB URI matching your Atlas configuration
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.8fclsxk.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
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
        req.decoded = decoded; // Payload is saved here consistently
        next();
    });
};

async function run() {
  try {
    await client.connect();
    
    const db = client.db("mediQueueDB");
    const tutorCollection = db.collection("tutors");
    const bookingCollection = db.collection("bookings");
    const userCollection = db.collection("users"); 

    console.log("🚀 Successfully connected to MongoDB Atlas!");

    // -------------------------------------------------------------------------
    // AUTHENTICATION & CUSTOM JWT ENDPOINTS
    // -------------------------------------------------------------------------
    
    // 1. POST: Register a new user manually with password hashing
    app.post('/register', async (req, res) => {
        try {
            const { name, email, photo, password } = req.body;

            // Check if user already exists
            const existingUser = await userCollection.findOne({ email });
            if (existingUser) {
                return res.status(400).send({ error: true, message: "An account with this email already exists." });
            }

            // Scramble password securely
            const hashedPassword = await bcrypt.hash(password, 10);

            const newUser = {
                name,
                email,
                photo,
                password: hashedPassword
            };

            const result = await userCollection.insertOne(newUser);
            res.send({ success: true, insertedId: result.insertedId });
        } catch (error) {
            res.status(500).send({ error: true, message: "Server error during registration workflow." });
        }
    });

    // 2. POST: Authenticate user, verify hashed password, and issue JWT
    app.post('/login', async (req, res) => {
        try {
            const { email, password } = req.body;

            // Look up user profile
            const user = await userCollection.findOne({ email });
            if (!user) {
                return res.status(401).send({ error: true, message: "Incorrect email or password combination." });
            }

            // Compare incoming text against the database hash string
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).send({ error: true, message: "Incorrect email or password combination." });
            }

            // Generate verified JWT token access pass
            const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

            res.send({
                success: true,
                token,
                user: {
                    name: user.name,
                    email: user.email,
                    photo: user.photo
                }
            });
        } catch (error) {
            res.status(500).send({ error: true, message: "Server error during login authentication processing." });
        }
    });

    // 3. POST: Generate JWT tokens specifically for real Google Console sign-ins
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

    // GET: Home page tutors (Limit to 6 cards)
    app.get('/tutors/home', async (req, res) => {
        const query = {};
        const result = await tutorCollection.find(query).limit(6).toArray();
        res.send(result);
    });

    // GET: Browse Tutors page with Search & Date Filters
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

    // GET: Fetch individual tutor profile specs (ALLOWED FOR GUESTS)
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

    // POST: Add a Tutor (Private Route)
    app.post('/tutors', verifyJWT, async (req, res) => {
        const newTutor = req.body;
        if (newTutor.totalSlot) newTutor.totalSlot = parseInt(newTutor.totalSlot);
        if (newTutor.hourlyFee) newTutor.hourlyFee = parseFloat(newTutor.hourlyFee);
        
        const result = await tutorCollection.insertOne(newTutor);
        res.send(result);
    });

    // GET: My Tutors list (Created by particular email)
    app.get('/my-tutors', verifyJWT, async (req, res) => {
        const email = req.query.email;
        // FIXED: Using req.decoded.email to match verification structure cleanly
        if (req.decoded.email !== email) {
            return res.status(403).send({ error: true, message: 'Forbidden access management context' });
        }
        const query = { createdBy: email };
        const result = await tutorCollection.find(query).toArray();
        res.send(result);
    });

    // PUT: Update tutor details
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

    // DELETE: Remove tutor profile
    app.delete('/tutors/:id', verifyJWT, async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await tutorCollection.deleteOne(query);
        res.send(result);
    });

    // -------------------------------------------------------------------------
    // BOOKINGS ENDPOINTS
    // -------------------------------------------------------------------------

    // POST: Book session with date checks and atomic slot updates
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

    // GET: My Booked Sessions list
    app.get('/my-bookings', verifyJWT, async (req, res) => {
        const email = req.query.email;
        // FIXED: Using req.decoded.email to match validation payload context cleanly
        if (req.decoded.email !== email) {
            return res.status(403).send({ error: true, message: 'Forbidden data extraction request' });
        }
        const query = { studentEmail: email };
        const result = await bookingCollection.find(query).toArray();
        res.send(result);
    });

    // PATCH: Cancel appointment tracking status
    app.patch('/bookings/:id/cancel', verifyJWT, async (req, res) => {
        const id = req.params.id;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
            $set: { status: 'cancelled' }
        };
        const result = await bookingCollection.updateOne(filter, updateDoc);
        res.send(result);
    });

    // DELETE: Cancel/Remove a booked session
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

  } catch (error) {
      console.error("❌ Fatal Database runtime execution context error:", error);
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('MediQueue Server is running beautifully.');
});

app.listen(port, () => {
    console.log(`Server executing seamlessly on port ${port}`);
});