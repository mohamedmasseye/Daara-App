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

// --- 1. IMPORTS CLOUDINARY ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ==========================================
// 0. CONFIGURATION FIREBASE (INCHANGÉ)
// ==========================================
const admin = require('firebase-admin');
try {
  const serviceAccount = require('./serviceAccountKey.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log("🔥 Firebase Admin connecté !");
} catch (error) {
  console.log("⚠️ Firebase non activé (fichier clé manquant).");
}

// ==========================================
// 1. INITIALISATION APP & MIDDLEWARES (INCHANGÉ)
// ==========================================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'daara_secret_key_super_securisee_123';

// Le dossier uploads n'est plus critique avec Cloudinary, mais on le garde pour éviter les erreurs
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// --- CONFIGURATION CORS (INCHANGÉE) ---
const allowedOrigins = [
  'https://daaraserignemordiop.vercel.app', 
  'http://localhost:3000',                  
  'http://localhost:5173'                   
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log("Bloqué par CORS:", origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(uploadDir));

// ==========================================
// 2. CONFIGURATION CLOUDINARY (REMPLACE MULTER DISK)
// ==========================================

// Config Cloudinary (Assurez-vous d'avoir ces variables dans votre .env sur Render)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Storage Engine Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'daara-uploads', // Nom du dossier dans votre Cloudinary
    allowed_formats: ['jpg', 'png', 'jpeg', 'pdf', 'mp3', 'webp'],
    resource_type: 'auto', // Important pour accepter PDF et Audio
  },
});

const upload = multer({ storage: storage });

// Définitions des uploads (Inchangé)
const productUploads = upload.array('productImages', 5);
const eventUploads = upload.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const bookUploads = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);
const blogUploads = upload.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
const mediaUploads = upload.single('mediaFile');
const avatarUpload = upload.single('avatar');

// NOTE: getFileUrl n'est plus nécessaire car Cloudinary renvoie directement l'URL complète dans req.file.path

// ==========================================
// 3. IMPORTS DES MODÈLES (INCHANGÉ)
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

// Middleware d'authentification (INCHANGÉ)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Accès refusé" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalide" });
    req.user = user;
    next();
  });
};

// ==========================================
// 4. ROUTES API (ADAPTÉES CLOUDINARY)
// ==========================================

// --- AUTHENTIFICATION ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, email, password } = req.body;
    const loginKey = identifier || email;
    if (!loginKey) return res.status(400).json({ error: "Email ou téléphone requis." });

    const user = await User.findOne({ $or: [{ email: loginKey }, { phone: loginKey }] });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: "Identifiants incorrects." });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, identifier, password } = req.body;
    if (!identifier) return res.status(400).json({ error: "Email/Téléphone requis." });

    const isEmail = identifier.includes('@');
    const email = isEmail ? identifier : undefined;
    const phone = !isEmail ? identifier : undefined;

    const exists = await User.findOne(isEmail ? { email } : { phone });
    if (exists) return res.status(400).json({ error: "Utilisateur déjà inscrit." });

    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ fullName, email, phone, password: hashedPassword }).save();
    
    res.status(201).json({ message: "Compte créé." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ error: "Token manquant" });
        const decodedToken = await admin.auth().verifyIdToken(token);
        const { uid, email, name, picture } = decodedToken;

        let user = await User.findOne({ $or: [{ googleId: uid }, { email: email }] });

        if (!user) {
            user = new User({
                fullName: name || "Utilisateur Google",
                email, googleId: uid, avatar: picture,
                authProvider: 'google', role: 'user'
            });
            await user.save();
        } else {
            if (!user.googleId) user.googleId = uid;
            if (!user.avatar) user.avatar = picture;
            await user.save();
        }
        const appToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token: appToken, user });
    } catch (err) {
        res.status(401).json({ error: "Auth Google échouée" });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try { const user = await User.findById(req.user.id).select('-password'); res.json(user); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/auth/me', authenticateToken, avatarUpload, async (req, res) => {
    try {
        const updateData = { ...req.body };
        // Cloudinary : on utilise req.file.path
        if (req.file) updateData.avatar = req.file.path;
        const updated = await User.findByIdAndUpdate(req.user.id, updateData, { new: true }).select('-password');
        res.json(updated);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- GESTION UTILISATEURS (ADMIN) ---
app.get('/api/users', authenticateToken, async (req, res) => {
    try { const users = await User.find().select('-password').sort({ createdAt: -1 }); res.json(users); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users', authenticateToken, async (req, res) => {
    try {
        const { fullName, identifier, password, role } = req.body;
        const isEmail = identifier.includes('@');
        const email = isEmail ? identifier : undefined;
        const phone = !isEmail ? identifier : undefined;

        const exists = await User.findOne({ $or: [{ email: identifier }, { phone: identifier }] });
        if (exists) return res.status(400).json({ error: "Utilisateur existe déjà." });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ fullName, email, phone, password: hashedPassword, role: role || 'user' });
        await newUser.save();
        res.status(201).json(newUser);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
    try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true }).select('-password');
        res.json(updatedUser);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id/reset-password', authenticateToken, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        await User.findByIdAndUpdate(req.params.id, { password: hashedPassword });
        res.json({ message: "Mot de passe réinitialisé." });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
    try { await User.findByIdAndDelete(req.params.id); res.json({ message: "Utilisateur supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- CATEGORIES ---
app.get('/api/categories', async (req, res) => {
    try {
        const { type } = req.query;
        const filter = type ? { type } : {};
        const categories = await Category.find(filter).sort({ name: 1 });
        res.json(categories);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/categories/:type', async (req, res) => {
    try {
        const categories = await Category.find({ type: req.params.type }).sort({ name: 1 });
        res.json(categories);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/categories', authenticateToken, async (req, res) => {
    try {
        const { name, type } = req.body;
        const formattedName = name.charAt(0).toUpperCase() + name.slice(1);
        const newCategory = new Category({ name: formattedName, type: type || 'product' });
        await newCategory.save();
        res.status(201).json(newCategory);
    } catch (err) { 
        if (err.code === 11000) return res.status(400).json({ error: "Existe déjà" });
        res.status(400).json({ error: "Erreur création" }); 
    }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
    try { await Category.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- EVENTS ---
app.get('/api/events', async (req, res) => {
    try { const events = await Event.find().sort({ date: 1 }); res.json(events); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/events', eventUploads, async (req, res) => {
    try {
        const img = req.files['eventImage']?.[0];
        const doc = req.files['eventDocument']?.[0];
        const evt = new Event({
            ...req.body,
            image: img ? img.path : null, // Cloudinary Path
            documentUrl: doc ? doc.path : null // Cloudinary Path
        });
        await evt.save();
        res.status(201).json(evt);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/events/:id', eventUploads, async (req, res) => {
    try {
        let updateData = { ...req.body };
        const img = req.files['eventImage']?.[0];
        const doc = req.files['eventDocument']?.[0];
        // Mise à jour si nouveaux fichiers
        if (img) updateData.image = img.path;
        if (doc) updateData.documentUrl = doc.path;
        
        const updated = await Event.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(updated);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/events/:id', authenticateToken, async (req, res) => {
    try { await Event.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- PRODUCTS ---
app.get('/api/products', async (req, res) => {
    try { const products = await Product.find().populate('category').sort({ createdAt: -1 }); res.json(products); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/products', productUploads, async (req, res) => {
    try {
        // Cloudinary : array de fichiers, on map sur .path
        const imageUrls = (req.files || []).map(f => f.path);
        const newProduct = new Product({ ...req.body, images: imageUrls });
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.put('/api/products/:id', productUploads, async (req, res) => {
    try {
        let updateData = { ...req.body };
        if (req.files && req.files.length > 0) {
            updateData.images = req.files.map(f => f.path);
        }
        const updated = await Product.findByIdAndUpdate(req.params.id, updateData, { new: true });
        res.json(updated);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try { await Product.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- BOOKS ---
app.get('/api/books', async (req, res) => {
    try { const books = await Book.find().sort({ createdAt: -1 }); res.json(books); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/books', bookUploads, async (req, res) => {
    try {
        const pdf = req.files['pdfFile']?.[0];
        const cover = req.files['coverImage']?.[0];
        const book = new Book({
            ...req.body,
            pdfUrl: pdf ? pdf.path : req.body.pdfUrl,
            coverUrl: cover ? cover.path : null
        });
        await book.save();
        res.status(201).json(book);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/books/:id', authenticateToken, async (req, res) => {
    try { await Book.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- BLOG ---
app.get('/api/blog', async (req, res) => {
    try { const posts = await BlogPost.find().sort({ createdAt: -1 }); res.json(posts); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/blog', blogUploads, async (req, res) => {
    try {
        const cover = req.files['coverImageFile']?.[0];
        const pdf = req.files['pdfDocumentFile']?.[0];
        const post = new BlogPost({
            ...req.body,
            coverImage: cover ? cover.path : null,
            pdfDocument: pdf ? pdf.path : null
        });
        await post.save();
        res.status(201).json(post);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/blog/:id', authenticateToken, async (req, res) => {
    try { await BlogPost.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- PODCASTS ---
app.get('/api/podcasts', async (req, res) => {
    try { const podcasts = await Podcast.find().sort({ createdAt: -1 }); res.json(podcasts); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/podcasts', podcastUploads, async (req, res) => {
    try {
        const audio = req.files['audioFile']?.[0];
        const cover = req.files['coverImageFile']?.[0];
        if (!audio) return res.status(400).json({ error: "Audio requis" });
        const podcast = new Podcast({
            ...req.body,
            audioUrl: audio.path,
            coverImage: cover ? cover.path : null
        });
        await podcast.save();
        res.status(201).json(podcast);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/podcasts/:id', authenticateToken, async (req, res) => {
    try { await Podcast.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- MEDIA (Galerie) ---
app.get('/api/media', async (req, res) => {
    try { const media = await Media.find().sort({ createdAt: -1 }); res.json(media); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/media', mediaUploads, async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Fichier requis" });
        const media = new Media({ ...req.body, url: req.file.path });
        await media.save();
        res.status(201).json(media);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/media/:id', authenticateToken, async (req, res) => {
    try { await Media.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- COMMANDES & BILLETS ---
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { user, items, totalAmount, paymentMethod, customerPhone, address } = req.body;
        let cleanPayment = paymentMethod;
        if (paymentMethod?.toLowerCase().includes('wave')) cleanPayment = 'Wave';
        if (paymentMethod?.toLowerCase().includes('orange') || paymentMethod === 'om') cleanPayment = 'Orange Money';

        const newOrder = new Order({ user, items, totalAmount, paymentMethod: cleanPayment, customerPhone, address: address || {}, status: 'Pending' });
        const savedOrder = await newOrder.save();

        const ticketItems = items.filter(item => item.type === 'ticket');
        if (ticketItems.length > 0) {
            for (const item of ticketItems) {
                const eventId = item.ticketEvent || item.product;
                if (eventId) {
                    for (let i = 0; i < item.quantity; i++) {
                        await new Ticket({ event: eventId, user: user, type: 'Standard', price: item.price, qrCode: `TKT-${savedOrder._id.toString().slice(-6)}-${Date.now()}-${i}` }).save();
                    }
                }
            }
        }
        res.status(201).json(savedOrder);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.get('/api/orders', async (req, res) => {
    try { const orders = await Order.find().populate('user', 'fullName email').sort({ createdAt: -1 }); res.json(orders); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const updatedOrder = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
        res.json(updatedOrder);
    } catch (err) { res.status(400).json({ error: "Erreur MAJ statut" }); }
});

app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
    try { 
        await Ticket.deleteMany({ qrCode: { $regex: req.params.id } });
        await Order.findByIdAndDelete(req.params.id); 
        res.json({ message: "Commande supprimée" }); 
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/my-orders', authenticateToken, async (req, res) => {
    try { const orders = await Order.find({ user: req.user.id }).sort({ createdAt: -1 }); res.json(orders); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/my-tickets', authenticateToken, async (req, res) => {
    try { const tickets = await Ticket.find({ user: req.user.id }).populate('event').sort({ createdAt: -1 }); res.json(tickets); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/tickets/:id', authenticateToken, async (req, res) => {
    try { await Ticket.findByIdAndDelete(req.params.id); res.json({ message: "Billet supprimé" }); }
    catch (err) { res.status(500).json({ error: "Erreur suppression billet" }); }
});

// --- NOTIFICATIONS ---
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try { const notifications = await Notification.find().sort({ date: -1 }); res.json(notifications); }
    catch (err) { res.status(500).json({ error: "Erreur serveur" }); }
});

app.post('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const { title, body, type, target } = req.body;
        const newNotif = new Notification({ title, body, type: type || 'info', target });
        await newNotif.save();
        
        if (admin.apps.length) {
            admin.messaging().send({ notification: { title, body }, topic: 'all_users' })
                .then(r => console.log('✈️ Push envoyé:', r))
                .catch(e => console.log('⚠️ Erreur Push:', e.message));
        }
        res.status(201).json(newNotif);
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/notifications/:id', authenticateToken, async (req, res) => {
    try { await Notification.findByIdAndDelete(req.params.id); res.json({ message: "Supprimée" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- CONTACT / MESSAGERIE ---
app.post('/api/contact', async (req, res) => {
    try {
        const newMessage = new Contact(req.body);
        await newMessage.save();
        res.status(201).json({ message: "Message envoyé." });
    } catch (err) { res.status(400).json({ error: err.message }); }
});

app.get('/api/contact', authenticateToken, async (req, res) => {
    try { const messages = await Contact.find().sort({ date: -1 }); res.json(messages); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/contact/:id', authenticateToken, async (req, res) => {
    try { await Contact.findByIdAndDelete(req.params.id); res.json({ message: "Message supprimé." }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- UPLOAD GÉNÉRIQUE (Admin Home) ---
app.post('/api/upload', upload.single('file'), (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "Fichier requis" });
        // Cloudinary path
        res.json({ url: req.file.path });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// 5. DÉMARRAGE DU SERVEUR
// ==========================================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://mohamedmasseye_db_user:Kmd789415!@cluster0.1clqeei.mongodb.net/daaraserignemordiop?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ Connecté à MongoDB ATLAS (En ligne)');
    
    // Création Admin Auto
    try {
        const adminEmail = "admin@daara.com";
        const adminExist = await User.findOne({ email: adminEmail });
        if (!adminExist) {
            const hashedPassword = await bcrypt.hash("password123", 10);
            await new User({ fullName: "Super Admin", email: adminEmail, password: hashedPassword, phone: "770000000", role: "admin" }).save();
            console.log("🎉 ADMIN CRÉÉ ! Email: admin@daara.com / Pass: password123");
        }
    } catch (e) { console.error("Erreur admin auto:", e); }
    
    app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur en ligne sur le port ${PORT}`));
  })
  .catch(err => {
      console.error('❌ Erreur critique MongoDB:', err);
  });