require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo'); 

const app = express();

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.json());
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',  
        sameSite: 'strict'
    },
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI, 
        collectionName: 'sessions' 
    })
}));

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to MongoDB Atlas");
}).catch((err) => {
    console.error("MongoDB connection error:", err);
});

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const secretSchema = new mongoose.Schema({
    content: String,
    submittedBy: String
});

const User = mongoose.model("User", userSchema);
const Secret = mongoose.model("Secret", secretSchema);

function isAuthenticated(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.redirect('/login');
        req.user = decoded;
        next();
    });
}

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/register', (req, res) => {
    res.render('register', { errorMessage: null, email: null });
});

app.post('/register', async (req, res) => {
    try {
        const { username: email, password, name } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;

        if (!emailRegex.test(email)) {
            return res.render("register", {
                errorMessage: "Invalid email format.",
                email: email
            });
        }

        if (!passwordRegex.test(password)) {
            return res.render("register", {
                errorMessage: "Password must be at least 6 characters, include uppercase, lowercase, and a number.",
                email: email
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("register", {
                errorMessage: "Email is already registered.",
                email: email
            });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).send("An error occurred during registration.");
    }
});

app.get('/login', (req, res) => {
    res.render('login', { errorMessage: null });
});

app.post('/login', async (req, res) => {
    try {
        const { username: email, password } = req.body;
        const user = await User.findOne({ email });

        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
            res.cookie('token', token, { httpOnly: true, secure: false, sameSite: 'strict' });
            res.redirect('/secrets');
        } else {
            res.render('login', {
                errorMessage: "Invalid username or password."
            });
        }
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send("An error occurred during login.");
    }
});

app.get('/secrets', isAuthenticated, async (req, res) => {
    try {
        const secrets = await Secret.find({});
        res.render('secrets', { secrets });
    } catch (err) {
        console.error("Fetching secrets error:", err);
        res.status(500).send("Unable to fetch secrets.");
    }
});

app.get('/submit', isAuthenticated, (req, res) => {
    res.render('submit');
});

app.post('/submit', isAuthenticated, async (req, res) => {
    try {
        const submittedBy = req.user.id;
        const newSecret = new Secret({
            content: req.body.secret,
            submittedBy
        });
        await newSecret.save();
        res.redirect('/secrets');
    } catch (err) {
        console.error("Secret submission error:", err);
        res.status(500).send("Error submitting secret.");
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
