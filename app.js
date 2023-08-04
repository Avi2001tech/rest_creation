const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Connect to MongoDB (replace 'your_mongodb_url' with your MongoDB connection string)
mongoose.connect('mongodb://localhost:27017/your_database_name', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Create a user schema and model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// ...

// Secret key for JWT
const secretKey = 'your_secret_key'; // Replace this with your secret key

// Helper function to generate JWT token
function generateToken(user) {
  return jwt.sign(user, secretKey, { expiresIn: '1h' }); // Token expires in 1 hour
}

// POST endpoint for user registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  try {
    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name: name,
      email: email,
      password: hashedPassword,
    });

    await user.save();

    // Generate a JWT token for the registered user
    const token = generateToken({ id: user._id, name: user.name, email: user.email });

    res.json({ id: user._id, name: user.name, email: user.email, token });
  } catch (err) {
    res.status(500).json({ error: 'Error during registration.' });
  }
});

// POST endpoint for user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Compare the hashed password with the input password using bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Generate a JWT token for the logged-in user
    const token = generateToken({ id: user._id, name: user.name, email: user.email });

    res.json({ id: user._id, name: user.name, email: user.email, token });
  } catch (err) {
    res.status(500).json({ error: 'Error during login.' });
  }
});

// Authentication middleware to check JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden.' });
    }

    req.user = user;
    next();
  });
}

// Protected GET endpoint that requires authentication
app.get('/protected', authenticateToken, (req, res) => {
  const user = req.user;

  res.json({ message: 'This is a protected endpoint.', user });
});

// ...

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

