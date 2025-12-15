/**************************************************
 * SERVER.JS – DAARA APP (RENDER + VERCEL READY)
 **************************************************/

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

/* ===============================
   FIREBASE (OPTIONNEL)
================================ */
const admin = require('firebase-admin');
try {
  const serviceAccount = require('./serviceAccountKey.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('🔥 Firebase Admin OK');
} catch {
  console.log('⚠️ Firebase désactivé (clé manquante)');
}

/* ===============================
   MODELS
================================ */
const User = require('./models/User');
const Event = require('./models/Event');
const Order = require('./models/Order');
const Ticket = require('./models/Ticket');
const Product = require('./models/Product');
const Category = require('./models/Category');
const BlogPost = require('./models/BlogPost');
const Podcast = require('./models/Podcast');
const Book = require('./models/Book');
const Media = require('./models/Media');
const Notification = require('./models/Notification');
const Contact = require('./models/Contact');

/* ===============================
   APP INIT
================================ */
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'daara_secret_key';

/* ===============================
   CORS (CORRECTION MAJEURE)
================================ */
const allowedOrigins = [
  'https://daaraserignemordiop.vercel.app',
  'http://localhost:3000'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('CORS NOT ALLOWED'));
  },
  credentials: false,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

/* ===============================
   MIDDLEWARES
================================ */
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(express.json());

/* ===============================
   UPLOADS
================================ */
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

app.use('/uploads', express.static(uploadDir));

const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (_, file, cb) => {
    const clean = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    cb(null, Date.now() + '-' + clean);
  }
});
const upload = multer({ storage });

const avatarUpload = upload.single('avatar');

/* ===============================
   AUTH MIDDLEWARE
================================ */
const authenticateToken = (req, res, next) => {
  const auth = req.headers.authorization;
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Accès refusé' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.user = decoded;
    next();
  });
};

const fileUrl = (req, name) =>
  name ? `${req.protocol}://${req.get('host')}/uploads/${name}` : null;

/* ===============================
   AUTH ROUTES
================================ */
const handleLogin = async (req, res) => {
  try {
    const { identifier, email, password } = req.body;
    const key = identifier || email;

    if (!key || !password)
      return res.status(400).json({ error: 'Identifiant requis' });

    const user = await User.findOne({
      $or: [{ email: key }, { phone: key }]
    });

    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: 'Identifiants incorrects' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

app.post('/api/auth/login', handleLogin);
app.post('/api/login', handleLogin);

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, identifier, password } = req.body;
    if (!identifier || !password)
      return res.status(400).json({ error: 'Champs manquants' });

    const isEmail = identifier.includes('@');
    const email = isEmail ? identifier : undefined;
    const phone = !isEmail ? identifier : undefined;

    const exists = await User.findOne({ $or: [{ email }, { phone }] });
    if (exists)
      return res.status(400).json({ error: 'Utilisateur existe déjà' });

    const hashed = await bcrypt.hash(password, 10);

    await new User({
      fullName,
      email,
      phone,
      password: hashed,
      role: 'user'
    }).save();

    res.status(201).json({ message: 'Compte créé' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  res.json(user);
});

app.put('/api/auth/me', authenticateToken, avatarUpload, async (req, res) => {
  const update = { ...req.body };
  if (req.file) update.avatar = fileUrl(req, req.file.filename);

  const user = await User.findByIdAndUpdate(req.user.id, update, {
    new: true
  }).select('-password');

  res.json(user);
});

/* ===============================
   EXAMPLE ROUTE TEST
================================ */
app.get('/api/health', (_, res) => {
  res.json({ status: 'OK', server: 'Daara API running 🚀' });
});

/* ===============================
   DB + SERVER START
================================ */
const MONGODB_URI =
  process.env.MONGODB_URI ||
  'mongodb+srv://<USER>:<PASS>@cluster.mongodb.net/db';

mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB connecté');

    // Admin auto
    const adminEmail = 'admin@daara.com';
    if (!(await User.findOne({ email: adminEmail }))) {
      const hash = await bcrypt.hash('password123', 10);
      await new User({
        fullName: 'Super Admin',
        email: adminEmail,
        phone: '770000000',
        password: hash,
        role: 'admin'
      }).save();
      console.log('👑 Admin créé');
    }

    app.listen(PORT, '0.0.0.0', () =>
      console.log(`🚀 Server live on port ${PORT}`)
    );
  })
  .catch(err => console.error('❌ MongoDB error:', err));