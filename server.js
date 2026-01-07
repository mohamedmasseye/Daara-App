require('dotenv').config();
const { OAuth2Client } = require('google-auth-library');
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const admin = require('firebase-admin');

// ==========================================
// 0. CONFIGURATION FIREBASE (VERSION ROBUSTE)
// ==========================================
try {
  let serviceAccount;
  let rawData = process.env.FIREBASE_SERVICE_ACCOUNT;

  if (rawData) {
    rawData = rawData.trim();
    if (rawData.startsWith('"') && rawData.endsWith('"')) rawData = rawData.slice(1, -1);
    if (!rawData.startsWith('{')) {
      try {
        const buffer = Buffer.from(rawData, 'base64');
        const decoded = buffer.toString('utf-8');
        if (decoded.startsWith('{')) rawData = decoded;
      } catch (e) {}
    }
    rawData = rawData.replace(/\\"/g, '"').replace(/\\\\n/g, '\\n');
    serviceAccount = JSON.parse(rawData);
    if (serviceAccount.private_key) serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log("🔥 Firebase Admin connecté avec succès !");
  } else {
    serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log("💻 Firebase Admin connecté en local.");
  }
} catch (error) {
  console.log("⚠️ Erreur Firebase :", error.message);
}

// ==========================================
// 1. INITIALISATION APP & MIDDLEWARES
// ==========================================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'daara_secret_key_super_securisee_123';

const allowedOrigins = [
  'https://app.daaraserignemordiop.com',
  'https://api.daaraserignemordiop.com',
  'capacitor://localhost',
  'http://localhost',
  'http://localhost:5173'
];

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || origin.startsWith('http://localhost')) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// ==========================================
// 2. CONFIGURATION CLOUDINARY & MULTER
// ==========================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { folder: 'daara-uploads', allowed_formats: ['jpg', 'png', 'jpeg', 'pdf', 'mp3', 'webp'], resource_type: 'auto' }
});

const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } });

// Définition des types d'uploads
const productUploads = upload.array('productImages', 5);
const eventUploads = upload.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const bookUploads = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);
const blogUploads = upload.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
const mediaUploads = upload.single('mediaFile');
const avatarUpload = upload.single('avatar');

// ==========================================
// 3. IMPORTS DES MODÈLES & AUTH
// ==========================================
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
const HomeContent = require('./models/HomeContent');

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Accès refusé" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalide" });
    req.user = user;
    next();
  });
};

// ==========================================
// 4. ROUTES API
// ==========================================

// --- NOTIFICATIONS & TOPICS ---
app.post('/api/notifications/subscribe', async (req, res) => {
  try {
    await admin.messaging().subscribeToTopic(req.body.token, 'all_users');
    res.json({ message: 'Abonné' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notifications', async (req, res) => {
  try { res.json(await Notification.find().sort({ date: -1 })); } catch (e) { res.status(500).send(e); }
});

app.post('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { title, body, type, url } = req.body;
    const newNotif = new Notification({ title, body, type: type || 'info' });
    await newNotif.save();
    
    if (admin.apps.length) {
      const message = {
        notification: {
        title: "📅 Nouvel Événement",
        body: "Cliquez pour découvrir les détails."
      },
      data: {
        // ✅ C'est ce champ que l'APK et le SW vont lire
        url: "/evenements?id=ID_DE_L_EVENEMENT", 
      },
      topic: "all_users"
      };
      await admin.messaging().send(message);
    }
    res.status(201).json(newNotif);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try { await Notification.findByIdAndDelete(req.params.id); res.json({ message: "Supprimée" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- AUTHENTIFICATION & PROFIL ---
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  const user = await User.findOne({ $or: [{ email: identifier }, { phone: identifier }] });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Identifiants incorrects" });
  const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, identifier, password } = req.body;
    const isEmail = identifier.includes('@');
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ fullName, email: isEmail ? identifier : undefined, phone: !isEmail ? identifier : undefined, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "Créé" });
  } catch (e) { res.status(400).json({ error: "Déjà inscrit" }); }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const decoded = await admin.auth().verifyIdToken(req.body.token);
    let user = await User.findOne({ email: decoded.email });
    if (!user) {
      user = new User({ fullName: decoded.name, email: decoded.email, googleId: decoded.uid, avatar: decoded.picture, role: 'user' });
      await user.save();
    }
    res.json({ token: jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' }), user });
  } catch (e) { res.status(401).json({ error: "Erreur Google" }); }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  res.json(await User.findById(req.user.id).select('-password'));
});

app.put('/api/auth/me', authenticateToken, avatarUpload, async (req, res) => {
  const update = { ...req.body };
  if (req.file) update.avatar = req.file.path;
  res.json(await User.findByIdAndUpdate(req.user.id, update, { new: true }));
});

// --- GESTION UTILISATEURS ---
app.get('/api/users', authenticateToken, async (req, res) => {
  res.json(await User.find().select('-password').sort({ createdAt: -1 }));
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "Supprimé" });
});

// --- CATEGORIES ---
app.get('/api/categories', async (req, res) => {
  const { type } = req.query;
  res.json(await Category.find(type ? { type } : {}).sort({ name: 1 }));
});

app.post('/api/categories', authenticateToken, async (req, res) => {
  try {
    const cat = new Category(req.body);
    await cat.save();
    res.status(201).json(cat);
  } catch (e) { res.status(400).json({ error: "Existe déjà" }); }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  await Category.findByIdAndDelete(req.params.id);
  res.json({ message: "Supprimé" });
});

// --- EVENEMENTS ---
app.get('/api/events', async (req, res) => {
  res.json(await Event.find().sort({ date: 1 }));
});

app.post('/api/events', authenticateToken, eventUploads, async (req, res) => {
  const evt = new Event({ ...req.body, image: req.files['eventImage']?.[0].path, documentUrl: req.files['eventDocument']?.[0].path });
  await evt.save();
  res.status(201).json(evt);
});

app.put('/api/events/:id', authenticateToken, eventUploads, async (req, res) => {
  const update = { ...req.body };
  if (req.files['eventImage']) update.image = req.files['eventImage'][0].path;
  if (req.files['eventDocument']) update.documentUrl = req.files['eventDocument'][0].path;
  res.json(await Event.findByIdAndUpdate(req.params.id, update, { new: true }));
});

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
  await Event.findByIdAndDelete(req.params.id);
  res.json({ message: "Supprimé" });
});

// --- BOUTIQUE (PRODUITS) ---
app.get('/api/products', async (req, res) => {
  res.json(await Product.find().populate('category').sort({ createdAt: -1 }));
});

app.post('/api/products', authenticateToken, productUploads, async (req, res) => {
  const images = (req.files || []).map(f => f.path);
  const prod = new Product({ ...req.body, images });
  await prod.save();
  res.status(201).json(prod);
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: "Supprimé" });
});

// --- LIVRES (BOOKS) ---
app.get('/api/books', async (req, res) => {
  res.json(await Book.find().sort({ createdAt: -1 }));
});

app.post('/api/books', authenticateToken, bookUploads, async (req, res) => {
  const book = new Book({ ...req.body, pdfUrl: req.files['pdfFile']?.[0].path, coverUrl: req.files['coverImage']?.[0].path });
  await book.save();
  res.status(201).json(book);
});

// --- BLOG ---
app.get('/api/blog', async (req, res) => {
  res.json(await BlogPost.find().sort({ createdAt: -1 }));
});

app.post('/api/blog', authenticateToken, blogUploads, async (req, res) => {
  const post = new BlogPost({ ...req.body, coverImage: req.files['coverImageFile']?.[0].path, pdfDocument: req.files['pdfDocumentFile']?.[0].path });
  await post.save();
  res.status(201).json(post);
});

app.put('/api/blog/:id/like', async (req, res) => {
  res.json(await BlogPost.findByIdAndUpdate(req.params.id, { $inc: { likes: 1 } }, { new: true }));
});

// --- PODCASTS ---
app.get('/api/podcasts', async (req, res) => {
  res.json(await Podcast.find().sort({ createdAt: -1 }));
});

app.post('/api/podcasts', authenticateToken, podcastUploads, async (req, res) => {
  const pod = new Podcast({ ...req.body, audioUrl: req.files['audioFile'][0].path, coverImage: req.files['coverImageFile']?.[0].path });
  await pod.save();
  res.status(201).json(pod);
});

// --- MEDIAS (GALERIE) ---
app.get('/api/media', async (req, res) => {
  res.json(await Media.find().sort({ createdAt: -1 }));
});

app.post('/api/media', authenticateToken, mediaUploads, async (req, res) => {
  const med = new Media({ ...req.body, url: req.file.path });
  await med.save();
  res.status(201).json(med);
});

// --- COMMANDES (ORDERS) ---
app.post('/api/orders', authenticateToken, async (req, res) => {
  const order = new Order({ ...req.body, status: 'Pending' });
  const saved = await order.save();
  const ticketItems = req.body.items.filter(i => i.type === 'ticket');
  for (const item of ticketItems) {
    for (let i = 0; i < item.quantity; i++) {
      await new Ticket({ event: item.ticketEvent, user: req.body.user, qrCode: `TKT-${saved._id.toString().slice(-4)}-${Date.now()}-${i}` }).save();
    }
  }
  res.status(201).json(saved);
});

app.get('/api/orders', authenticateToken, async (req, res) => {
  res.json(await Order.find().populate('user', 'fullName email').sort({ createdAt: -1 }));
});

app.get('/api/my-orders', authenticateToken, async (req, res) => {
  res.json(await Order.find({ user: req.user.id }).sort({ createdAt: -1 }));
});

app.get('/api/my-tickets', authenticateToken, async (req, res) => {
  res.json(await Ticket.find({ user: req.user.id }).populate('event').sort({ createdAt: -1 }));
});

// --- HOME CONTENT ---
app.get('/api/home-content', async (req, res) => {
  const content = await HomeContent.findOne();
  res.json(content || {});
});

app.post('/api/home-content', authenticateToken, async (req, res) => {
  await HomeContent.deleteMany({});
  const content = new HomeContent(req.body);
  await content.save();
  res.status(201).json(content);
});

// --- CONTACT & UPLOAD ---
app.post('/api/contact', async (req, res) => {
  const msg = new Contact(req.body);
  await msg.save();
  res.status(201).json({ message: "Envoyé" });
});

app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  res.json({ url: req.file.path });
});

// ==========================================
// 5. DÉMARRAGE DU SERVEUR
// ==========================================
mongoose.connect(process.env.MONGO_URI || process.env.MONGODB_URI)
  .then(async () => {
    console.log('✅ MongoDB Connecté');
    const adminExist = await User.findOne({ email: "admin@daara.com" });
    if (!adminExist) {
        const hashedPassword = await bcrypt.hash("password123", 10);
        await new User({ fullName: "Super Admin", email: "admin@daara.com", password: hashedPassword, role: "admin" }).save();
    }
  })
  .catch(err => console.error('❌ Erreur MongoDB:', err));

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur actif sur le port ${PORT}`));