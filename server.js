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
const Log = require('./models/Log');
const os = require('os');

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
  params: { folder: 'daara-uploads', allowed_formats: ['jpg', 'png', 'jpeg', 'pdf', 'mp3', 'webp','avif'], resource_type: 'auto' }
});

const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } });
const productUploads = upload.array('productImages', 5);
const eventUploads = upload.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const bookUploads = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);
const blogUploads = upload.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
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

// Middleware supplémentaire pour vérifier si c'est un ADMIN
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Privilèges insuffisants." });
    }
};

// ==========================================
// 4. TOUTES LES ROUTES API
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
  try {
    const update = { ...req.body };
    if (req.file) update.avatar = req.file.path;

    // Les champs phone et email ont un index unique+sparse : une chaîne vide ""
    // est considérée comme une valeur réelle et provoque E11000 si plusieurs
    // utilisateurs ont phone:"". On doit retirer le champ entièrement via $unset.
    const unset = {};
    if (update.phone === '' || update.phone === null) { unset.phone = 1; delete update.phone; }
    if (update.email === '' || update.email === null) { unset.email = 1; delete update.email; }

    const ops = { $set: update };
    if (Object.keys(unset).length) ops.$unset = unset;

    const user = await User.findByIdAndUpdate(req.user.id, ops, { new: true });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de la mise à jour du profil." });
  }
});

// ✅ SUPPRESSION DU COMPTE (Nécessaire Play Store 2026)
app.delete('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    // On nettoie les données liées pour respecter le "Droit à l'oubli"
    await Order.deleteMany({ user: userId });
    await Ticket.deleteMany({ user: userId });
    const deletedUser = await User.findByIdAndDelete(userId);
    if (!deletedUser) return res.status(404).json({ error: "Utilisateur non trouvé" });
    res.json({ message: "Compte et données associés supprimés avec succès." });
  } catch (error) {
    res.status(500).json({ error: "Erreur lors de la suppression." });
  }
});

// --- AUTHENTIFICATION GOOGLE ---
app.post('/api/auth/google', async (req, res) => {
  try {
    const idToken = req.body.token || req.body.idToken || req.body.credential;
    if (!idToken) return res.status(400).json({ error: "Token manquant." });
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { email, name, picture, uid } = decodedToken;
    let user = await User.findOne({ $or: [{ email }, { googleId: uid }] });
    if (!user) {
      user = new User({ fullName: name, email, avatar: picture, googleId: uid, role: 'user' });
      await user.save();
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (error) {
    res.status(401).json({ error: "Session Google invalide." });
  }
});

app.post('/api/auth/google-mobile', async (req, res) => {
  try {
    const idToken = req.body.token || req.body.idToken || req.body.authentication?.idToken;
    if (!idToken) return res.status(400).json({ error: "Jeton Google manquant." });
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken: idToken, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;
    let user = await User.findOne({ $or: [{ email }, { googleId }] });
    if (!user) {
      user = new User({ fullName: name, email, avatar: picture, googleId, role: 'user' });
      await user.save();
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user });
  } catch (error) {
    res.status(400).json({ error: "Authentification Google mobile échouée." });
  }
});

// --- GESTION UTILISATEURS (ADMIN) ---
app.get('/api/users', authenticateToken, async (req, res) => {
  res.json(await User.find().select('-password').sort({ createdAt: -1 }));
});


// ✅ AJOUT ROUTE : CRÉER UN UTILISATEUR (MANQUANT)
app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { fullName, identifier, role, password } = req.body;
        const isEmail = identifier.includes('@');
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newUser = new User({ 
            fullName, 
            email: isEmail ? identifier : undefined, 
            phone: !isEmail ? identifier : undefined, 
            password: hashedPassword,
            role: role || 'user'
        });

        await newUser.save();
        // On retourne l'utilisateur sans le mot de passe
        const userResponse = newUser.toObject();
        delete userResponse.password;
        res.status(201).json(userResponse);
    } catch (e) { 
        res.status(400).json({ error: "L'identifiant est déjà utilisé." }); 
    }
});

// ✅ AJOUT ROUTE : MODIFIER UN UTILISATEUR (MANQUANT)
app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { fullName, role } = req.body;
        const updated = await User.findByIdAndUpdate(
            req.params.id, 
            { fullName, role }, 
            { new: true }
        ).select('-password');
        res.json(updated);
    } catch (e) { res.status(400).json({ error: "Erreur lors de la mise à jour." }); }
});

// ✅ AJOUT ROUTE : RESET PASSWORD PAR ADMIN (MANQUANT)
app.put('/api/users/:id/reset-password', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { newPassword } = req.body;
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await User.findByIdAndUpdate(req.params.id, { password: hashedPassword });
        res.json({ message: "Mot de passe mis à jour." });
    } catch (e) { res.status(400).json({ error: "Erreur reset password." }); }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "Utilisateur supprimé" });
});

// --- LIVRES ---
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

// --- PRODUITS ---
app.get('/api/products', async (req, res) => { res.json(await Product.find().populate('category').sort({ createdAt: -1 })); });
app.post('/api/products', authenticateToken, productUploads, async (req, res) => {
  const images = (req.files || []).map(f => f.path);
  const prod = new Product({ ...req.body, images });
  await prod.save();
  res.status(201).json(prod);
});
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
app.get('/api/categories/:type', async (req, res) => {
  try {
    const list = await Category.find({ type: req.params.type }).sort({ name: 1 });
    res.json(list);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
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

// --- EVENEMENTS ---
app.get('/api/events', async (req, res) => { res.json(await Event.find().sort({ date: 1 })); });
app.post('/api/events', authenticateToken, eventUploads, async (req, res) => {
  const evt = new Event({ ...req.body, image: req.files['eventImage']?.[0].path, documentUrl: req.files['eventDocument']?.[0].path });
  await evt.save();
  res.status(201).json(evt);
});
app.put('/api/events/:id', authenticateToken, eventUploads, async (req, res) => {
  try {
    const update = { ...req.body };
    
    // Nettoyage des dates pour éviter les erreurs de "Cast"
    if (!update.date || update.date === "Invalid Date") delete update.date;
    if (!update.endDate || update.endDate === "" || update.endDate === "Invalid Date") {
        update.endDate = null; // On force à null si c'est vide
    }

    if (req.files['eventImage']) update.image = req.files['eventImage'][0].path;
    if (req.files['eventDocument']) update.documentUrl = req.files['eventDocument'][0].path;
    
    const updatedEvent = await Event.findByIdAndUpdate(req.params.id, update, { new: true });
    res.json(updatedEvent);
  } catch (error) {
    console.error("Erreur Update Event:", error);
    res.status(500).json({ error: "Erreur lors de la mise à jour." });
  }
});

// --- BLOG ---
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

// --- MÉDIATHÈQUE ---
app.get('/api/media', async (req, res) => { res.json(await Media.find().sort({ createdAt: -1 })); });
app.post('/api/media', authenticateToken, mediaUploads, async (req, res) => {
  const med = new Media({ title: req.body.title, category: req.body.category, type: req.body.type, url: req.file.path });
  await med.save();
  res.status(201).json(med);
});
app.put('/api/media/:id', authenticateToken, async (req, res) => {
  res.json(await Media.findByIdAndUpdate(req.params.id, req.body, { new: true }));
});
app.delete('/api/media/:id', authenticateToken, async (req, res) => {
  await Media.findByIdAndDelete(req.params.id);
  res.json({ message: "Élément supprimé" });
});

// --- PODCASTS ---
app.get('/api/podcasts', async (req, res) => { res.json(await Podcast.find().sort({ createdAt: -1 })); });
app.post('/api/podcasts', authenticateToken, podcastUploads, async (req, res) => {
  const pod = new Podcast({ ...req.body, audioUrl: req.files['audioFile'][0].path, coverImage: req.files['coverImageFile']?.[0].path });
  await pod.save();
  res.status(201).json(pod);
});
app.put('/api/podcasts/:id', authenticateToken, podcastUploads, async (req, res) => {
  try {
    const updateData = { ...req.body };
    if (req.files) {
      if (req.files['audioFile']?.length > 0) updateData.audioUrl = req.files['audioFile'][0].path;
      if (req.files['coverImageFile']?.length > 0) updateData.coverImage = req.files['coverImageFile'][0].path;
    }
    const updatedPodcast = await Podcast.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updatedPodcast) return res.status(404).json({ error: "Podcast non trouvé" });
    res.json(updatedPodcast);
  } catch (e) { console.error("❌ Erreur lors de la modification du Podcast:", e.message); res.status(500).json({ error: "Erreur serveur." }); }
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

// --- NOTIFICATIONS & HOME ---
app.get('/api/notifications', authenticateToken, async (req, res) => { res.json(await Notification.find().sort({ date: -1 })); });
app.post('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { title, body, type } = req.body;
    const newNotif = new Notification({ title, body, type, date: new Date() });
    await newNotif.save();
    try {
      await admin.messaging().send({ notification: { title, body }, topic: 'all_users' });
    } catch (fcmError) { console.log("⚠️ FCM Error:", fcmError.message); }
    res.status(201).json(newNotif);
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/notifications/subscribe', async (req, res) => {
  try {
    if (req.body.token) await admin.messaging().subscribeToTopic(req.body.token, 'all_users');
    res.json({ message: "Abonnement réussi" });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
  await Notification.findByIdAndDelete(req.params.id);
  res.json({ message: "Supprimée" });
});
app.get('/api/home-content', async (req, res) => { try { const content = await HomeContent.findOne(); res.json(content || {}); } catch (e) { res.json({}); } });
app.post('/api/home-content', authenticateToken, async (req, res) => {
  await HomeContent.deleteMany({});
  const content = new HomeContent(req.body);
  await content.save();
  res.status(201).json(content);
});

// --- UPLOAD GÉNÉRIQUE ---
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
  res.json({ url: req.file.path });
});

app.get('/api/admin/system-health', authenticateToken, isAdmin, async (req, res) => {
  const health = {
    uptime: process.uptime(),
    message: 'OK',
    timestamp: Date.now(),
    mongoConnection: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
    memoryUsage: process.memoryUsage(),
    osLoad: require('os').loadavg(),
  };
  res.json(health);
});

// 1. Statistiques vitales du serveur
app.get('/api/admin/monitoring/stats', authenticateToken, isAdmin, async (req, res) => {
  const stats = {
    uptime: process.uptime(),
    platform: process.platform,
    memory: {
      free: Math.round(os.freemem() / 1024 / 1024),
      total: Math.round(os.totalmem() / 1024 / 1024),
      usage: Math.round((process.memoryUsage().heapUsed / 1024 / 1024))
    },
    database: mongoose.connection.readyState === 1 ? 'Connecté' : 'Erreur',
    version: "1.2.0-stable", // Ta version actuelle
    lastDeploy: fs.statSync(__filename).mtime // Date du dernier redémarrage
  };
  res.json(stats);
});

// 2. Récupérer les derniers logs d'erreurs
app.get('/api/admin/monitoring/logs', authenticateToken, isAdmin, async (req, res) => {
  const logs = await Log.find().sort({ timestamp: -1 }).limit(20).populate('userId', 'fullName');
  res.json(logs);
});

// 3. Vider les logs
app.delete('/api/admin/monitoring/logs', authenticateToken, isAdmin, async (req, res) => {
  await Log.deleteMany({});
  res.json({ message: "Logs nettoyés" });
});

// ✅ MIDDLEWARE CAPTUREUR D'ERREUR (À mettre tout à la fin de server.js, après les routes)
app.use(async (err, req, res, next) => {
  console.error(err.stack);
  // On enregistre l'erreur en base de données automatiquement !
  await new Log({
    message: err.message,
    path: req.path,
    method: req.method,
    stack: err.stack,
    userId: req.user ? req.user.id : null
  }).save();

  res.status(500).json({ error: "Erreur interne du serveur." });
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