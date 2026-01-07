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
const rateLimit = require('express-rate-limit');

// ==========================================
// 0. CONFIGURATION FIREBASE
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
  } else {
    serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  }
} catch (error) { console.log("⚠️ Erreur Firebase :", error.message); }

// ==========================================
// 1. INITIALISATION APP & MIDDLEWARES
// ==========================================
const app = express();
app.set('trust proxy', 1);
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

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10, 
  message: { error: "Trop de tentatives. Réessayez dans 15 min." }
});
app.use('/api/auth/login', loginLimiter);

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
const productUploads = upload.array('productImages', 5);
const eventUploads = upload.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const bookUploads = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);
const blogUploads = upload.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
// ✅ AJOUTS DES DÉFINITIONS MANQUANTES
const mediaUploads = upload.single('mediaFile');
const avatarUpload = upload.single('avatar');

// ==========================================
// 3. IMPORTS DES MODÈLES & AUTH MIDDLEWARE
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
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Accès refusé" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Session invalide" });
    req.user = user;
    next();
  });
};

// ==========================================
// 4. TOUTES LES ROUTES API (CRUD COMPLET)
// ==========================================

// --- AUTHENTIFICATION ---
app.post('/api/auth/login', async (req, res) => {
  const { identifier, password } = req.body;
  const user = await User.findOne({ $or: [{ email: identifier }, { phone: identifier }] });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Identifiants incorrects" });
  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, identifier, password } = req.body;
    const isEmail = identifier.includes('@');
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ fullName, email: isEmail ? identifier : undefined, phone: !isEmail ? identifier : undefined, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "Compte créé" });
  } catch (e) { res.status(400).json({ error: "Email ou téléphone déjà utilisé" }); }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  res.json(await User.findById(req.user.id).select('-password'));
});

app.put('/api/auth/me', authenticateToken, avatarUpload, async (req, res) => {
  const update = { ...req.body };
  if (req.file) update.avatar = req.file.path;
  const user = await User.findByIdAndUpdate(req.user.id, update, { new: true });
  res.json(user);
});

// --- GESTION UTILISATEURS (ADMIN) ---
app.get('/api/users', authenticateToken, async (req, res) => {
  res.json(await User.find().select('-password').sort({ createdAt: -1 }));
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "Utilisateur supprimé" });
});

// --- LIVRES (CRUD) ---
app.get('/api/books', async (req, res) => { res.json(await Book.find().sort({ createdAt: -1 })); });

app.post('/api/books', authenticateToken, bookUploads, async (req, res) => {
  const book = new Book({ ...req.body, pdfUrl: req.files['pdfFile']?.[0]?.path, coverUrl: req.files['coverImage']?.[0]?.path });
  await book.save();
  res.status(201).json(book);
});

app.put('/api/books/:id', authenticateToken, bookUploads, async (req, res) => {
  const update = { ...req.body };
  if (req.files['pdfFile']) update.pdfUrl = req.files['pdfFile'][0].path;
  if (req.files['coverImage']) update.coverUrl = req.files['coverImage'][0].path;
  res.json(await Book.findByIdAndUpdate(req.params.id, update, { new: true }));
});

app.delete('/api/books/:id', authenticateToken, async (req, res) => {
  await Book.findByIdAndDelete(req.params.id);
  res.json({ message: "Livre supprimé" });
});

// --- BOUTIQUE / PRODUITS (CRUD) ---
app.get('/api/products', async (req, res) => { res.json(await Product.find().populate('category').sort({ createdAt: -1 })); });

app.post('/api/products', authenticateToken, productUploads, async (req, res) => {
  const images = (req.files || []).map(f => f.path);
  const prod = new Product({ ...req.body, images });
  await prod.save();
  res.status(201).json(prod);
});

// ✅ AJOUT ROUTE PUT PRODUITS
app.put('/api/products/:id', authenticateToken, productUploads, async (req, res) => {
  const update = { ...req.body };
  if (req.files && req.files.length > 0) update.images = req.files.map(f => f.path);
  res.json(await Product.findByIdAndUpdate(req.params.id, update, { new: true }));
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: "Produit supprimé" });
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

app.put('/api/categories/:id', authenticateToken, async (req, res) => {
  res.json(await Category.findByIdAndUpdate(req.params.id, req.body, { new: true }));
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  await Category.findByIdAndDelete(req.params.id);
  res.json({ message: "Supprimée" });
});

// --- EVENEMENTS (CRUD) ---
app.get('/api/events', async (req, res) => { res.json(await Event.find().sort({ date: 1 })); });

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
  res.json({ message: "Événement supprimé" });
});

// --- BLOG (CRUD) ---
app.get('/api/blog', async (req, res) => { res.json(await BlogPost.find().sort({ createdAt: -1 })); });

app.post('/api/blog', authenticateToken, blogUploads, async (req, res) => {
  const post = new BlogPost({ ...req.body, coverImage: req.files['coverImageFile']?.[0].path, pdfDocument: req.files['pdfDocumentFile']?.[0].path });
  await post.save();
  res.status(201).json(post);
});

app.put('/api/blog/:id', authenticateToken, blogUploads, async (req, res) => {
  const update = { ...req.body };
  if (req.files['coverImageFile']) update.coverImage = req.files['coverImageFile'][0].path;
  if (req.files['pdfDocumentFile']) update.pdfDocument = req.files['pdfDocumentFile'][0].path;
  res.json(await BlogPost.findByIdAndUpdate(req.params.id, update, { new: true }));
});

app.post('/api/blog/:id/comment', authenticateToken, async (req, res) => {
  const post = await BlogPost.findByIdAndUpdate(req.params.id, { $push: { comments: req.body } }, { new: true });
  res.json(post);
});

app.put('/api/blog/:id/like', async (req, res) => {
  res.json(await BlogPost.findByIdAndUpdate(req.params.id, { $inc: { likes: 1 } }, { new: true }));
});

app.delete('/api/blog/:id', authenticateToken, async (req, res) => {
  await BlogPost.findByIdAndDelete(req.params.id);
  res.json({ message: "Article supprimé" });
});

// --- MÉDIATHÈQUE / GALERIE ---
app.get('/api/media', async (req, res) => {
  try {
    res.json(await Media.find().sort({ createdAt: -1 }));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/media', authenticateToken, mediaUploads, async (req, res) => {
  try {
    const med = new Media({ 
      title: req.body.title,
      category: req.body.category,
      type: req.body.type,
      url: req.file.path
    });
    await med.save();
    res.status(201).json(med);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ✅ AJOUT ROUTE PUT MÉDIA
app.put('/api/media/:id', authenticateToken, async (req, res) => {
  res.json(await Media.findByIdAndUpdate(req.params.id, req.body, { new: true }));
});

app.delete('/api/media/:id', authenticateToken, async (req, res) => {
  try {
    await Media.findByIdAndDelete(req.params.id);
    res.json({ message: "Élément supprimé" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- PODCASTS (CRUD) ---
app.get('/api/podcasts', async (req, res) => { res.json(await Podcast.find().sort({ createdAt: -1 })); });

app.post('/api/podcasts', authenticateToken, podcastUploads, async (req, res) => {
  const pod = new Podcast({ ...req.body, audioUrl: req.files['audioFile'][0].path, coverImage: req.files['coverImageFile']?.[0].path });
  await pod.save();
  res.status(201).json(pod);
});

app.put('/api/podcasts/:id', authenticateToken, podcastUploads, async (req, res) => {
  const update = { ...req.body };
  if (req.files['audioFile']) update.audioUrl = req.files['audioFile'][0].path;
  if (req.files['coverImageFile']) update.coverImage = req.files['coverImageFile'][0].path;
  res.json(await Podcast.findByIdAndUpdate(req.params.id, update, { new: true }));
});

app.delete('/api/podcasts/:id', authenticateToken, async (req, res) => {
  await Podcast.findByIdAndDelete(req.params.id);
  res.json({ message: "Podcast supprimé" });
});

// --- COMMANDES & BILLETS ---
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

app.get('/api/orders', authenticateToken, async (req, res) => { res.json(await Order.find().populate('user', 'fullName email').sort({ createdAt: -1 })); });
app.get('/api/my-orders', authenticateToken, async (req, res) => { res.json(await Order.find({ user: req.user.id }).sort({ createdAt: -1 })); });
app.get('/api/my-tickets', authenticateToken, async (req, res) => { res.json(await Ticket.find({ user: req.user.id }).populate('event').sort({ createdAt: -1 })); });

app.put('/api/orders/:id', authenticateToken, async (req, res) => {
  const order = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
  res.json(order);
});

app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
  await Order.findByIdAndDelete(req.params.id);
  res.json({ message: "Commande supprimée" });
});

// --- MESSAGES DE CONTACT ---
app.get('/api/contact', authenticateToken, async (req, res) => { res.json(await Contact.find().sort({ createdAt: -1 })); });
app.post('/api/contact', async (req, res) => {
  const msg = new Contact(req.body);
  await msg.save();
  res.status(201).json({ message: "Envoyé" });
});
app.delete('/api/contact/:id', authenticateToken, async (req, res) => {
  await Contact.findByIdAndDelete(req.params.id);
  res.json({ message: "Message supprimé" });
});

// 1. Récupérer l'historique (Indispensable pour l'affichage Admin)
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const list = await Notification.find().sort({ date: -1 });
    res.json(list);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2. Envoyer une notification (Sauvegarde + Envoi Mobile via Firebase)
app.post('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { title, body, type } = req.body;
    
    // Sauvegarde en base de données
    const newNotif = new Notification({ title, body, type, date: new Date() });
    await newNotif.save();

    // Envoi réel aux smartphones via Firebase Cloud Messaging
    const payload = {
      notification: { title, body },
      topic: 'all_users'
    };

    try {
      await admin.messaging().send(payload);
      console.log("Notification push envoyée au topic all_users");
    } catch (fcmError) {
      console.log("⚠️ Erreur d'envoi FCM (Firebase non configuré ?)", fcmError.message);
    }

    res.status(201).json(newNotif);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// 3. S'abonner aux notifications (Utilisé par NotificationBanner.jsx)
app.post('/api/notifications/subscribe', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Token manquant" });
    
    // Abonnement du token au topic global
    await admin.messaging().subscribeToTopic(token, 'all_users');
    res.json({ message: "Abonnement réussi" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4. Supprimer une notification de l'historique
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try {
      await Notification.findByIdAndDelete(req.params.id);
      res.json({ message: "Supprimée" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5. Contenu de la page d'accueil
app.get('/api/home-content', async (req, res) => { 
    try {
      const content = await HomeContent.findOne();
      res.json(content || {}); 
    } catch (e) { res.json({}); }
});

app.post('/api/home-content', authenticateToken, async (req, res) => {
  try {
    await HomeContent.deleteMany({});
    const content = new HomeContent(req.body);
    await content.save();
    res.status(201).json(content);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// --- UPLOAD GÉNÉRIQUE ---
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