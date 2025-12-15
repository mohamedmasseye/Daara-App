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

// ==========================================
// 0. CONFIGURATION FIREBASE
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
// 1. INITIALISATION APP & MIDDLEWARES
// ==========================================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'daara_secret_key_super_securisee_123';

// Dossier Uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// --- CORRECTION CORS CRITIQUE ---
const allowedOrigins = [
  'https://daaraserignemordiop.vercel.app', // Votre Frontend Vercel
  'http://localhost:3000',                  // Dev local
  'http://localhost:5173'                   // Vite dev local (au cas où)
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
  credentials: true, // IMPORTANT pour le login
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors(corsOptions)); // Utilisation de la config personnalisée
app.use(express.json());
app.use('/uploads', express.static(uploadDir));

// ==========================================
// 2. CONFIGURATION MULTER (Uploads)
// ==========================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const cleanName = file.originalname.replace(/[^a-zA-Z0-9.]/g, "_");
    cb(null, Date.now() + '-' + cleanName);
  }
});
const upload = multer({ storage: storage });

// Définitions des uploads
const productUploads = upload.array('productImages', 5);
const eventUploads = upload.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = upload.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const bookUploads = upload.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);
const blogUploads = upload.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
const mediaUploads = upload.single('mediaFile');
const avatarUpload = upload.single('avatar');

// --- CORRECTION HTTPS CRITIQUE (Mixed Content) ---
// Force HTTPS pour les URLs générées sur Render
const getFileUrl = (req, filename) => {
  if (!filename) return null;
  const host = req.get('host');
  // Si on est en local (localhost), on garde http, sinon https
  const protocol = host.includes('localhost') ? 'http' : 'https';
  return `${protocol}://${host}/uploads/${filename}`;
};

// ==========================================
// 3. IMPORTS DES MODÈLES
// ==========================================
// Assurez-vous que ces fichiers existent bien dans ./models/
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

// Middleware d'authentification
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
// 4. ROUTES API
// ==========================================

// --- AUTH ---
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
        if (req.file) updateData.avatar = getFileUrl(req, req.file.filename);
        const updated = await User.findByIdAndUpdate(req.user.id, updateData, { new: true }).select('-password');
        res.json(updated);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- USERS ---
app.get('/api/users', authenticateToken, async (req, res) => {
    try { const users = await User.find().select('-password').sort({ createdAt: -1 }); res.json(users); }
    catch (err) { res.status(500).json({ error: err.message }); }
});
// (Ajoutez ici les autres routes users create/update/delete/reset...)

// --- EVENTS ---
app.get('/api/events', async (req, res) => {
    try { const events = await Event.find().sort({ date: 1 }); res.json(events); }
    catch (err) { res.status(500).json({ error: err.message }); }
});
// (Ajoutez ici les routes POST/PUT/DELETE events avec eventUploads et getFileUrl...)

// --- PRODUCTS ---
app.get('/api/products', async (req, res) => {
    try { const products = await Product.find().populate('category').sort({ createdAt: -1 }); res.json(products); }
    catch (err) { res.status(500).json({ error: err.message }); }
});
// (Ajoutez ici POST/PUT/DELETE products avec productUploads et getFileUrl...)

// --- BOOKS / BLOG / MEDIA / PODCASTS (Modèle générique pour les fichiers) ---
// Veillez à utiliser getFileUrl(req, file.filename) dans vos routes POST/PUT existantes
// Exemple pour Books:
app.get('/api/books', async (req, res) => {
    try { const books = await Book.find().sort({ createdAt: -1 }); res.json(books); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/books', bookUploads, async (req, res) => {
    try {
        const pdf = req.files['pdfFile']?.[0];
        const cover = req.files['coverImage']?.[0];
        const book = new Book({
            ...req.body,
            pdfUrl: getFileUrl(req, pdf?.filename),
            coverUrl: getFileUrl(req, cover?.filename)
        });
        await book.save();
        res.status(201).json(book);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
// (Répétez la logique pour Blog, Media, Podcast avec les bons champs)

// --- ORDERS ---
app.get('/api/my-orders', authenticateToken, async (req, res) => {
    try { const orders = await Order.find({ user: req.user.id }).sort({ createdAt: -1 }); res.json(orders); }
    catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/my-tickets', authenticateToken, async (req, res) => {
    try { const tickets = await Ticket.find({ user: req.user.id }).populate('event').sort({ createdAt: -1 }); res.json(tickets); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// ==========================================
// 5. DÉMARRAGE DU SERVEUR (Unique & Sécurisé)
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
            await new User({ 
                fullName: "Super Admin", 
                email: adminEmail, 
                password: hashedPassword, 
                phone: "770000000", 
                role: "admin" 
            }).save();
            console.log("🎉 ADMIN CRÉÉ ! Email: admin@daara.com / Pass: password123");
        }
    } catch (e) { console.error("Erreur admin auto:", e); }

    // DÉMARRAGE UNIQUE DU SERVEUR ICI
    app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Serveur en ligne sur le port ${PORT}`));
  })
  .catch(err => {
      console.error('❌ Erreur critique MongoDB:', err);
      // Ne pas démarrer le serveur si la DB échoue
  });