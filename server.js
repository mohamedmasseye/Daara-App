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

// --- 1. IMPORTS CLOUDINARY ---
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

// ==========================================
// 0. CONFIGURATION FIREBASE
// ==========================================
const admin = require('firebase-admin');

try {
  let serviceAccount;
  let rawData = process.env.FIREBASE_SERVICE_ACCOUNT;

  if (rawData) {
    rawData = rawData.trim();
    if (rawData.startsWith('"') && rawData.endsWith('"')) rawData = rawData.slice(1, -1);
    if (!rawData.startsWith('{')) {
      try {
        const decoded = Buffer.from(rawData, 'base64').toString('utf-8');
        if (decoded.startsWith('{')) rawData = decoded;
      } catch (e) {}
    }
    rawData = rawData.replace(/\\"/g, '"').replace(/\\\\n/g, '\\n');
    serviceAccount = JSON.parse(rawData);
    if (serviceAccount.private_key) serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');

    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log("🔥 Firebase Admin connecté !");
  } else {
    serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log("💻 Firebase Local.");
  }
} catch (error) {
  console.log("⚠️ Erreur Firebase :", error.message);
}

// ==========================================
// 1. INITIALISATION APP
// ==========================================
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'daara_secret';

// ✅ Dossier temporaire pour les gros uploads (Livres)
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// --- CORS ---
const allowedOrigins = [
  'http://pok408wwkw084ckk0ogscsgw.91.99.200.188.sslip.io',
  'https://pok408wwkw084ckk0ogscsgw.91.99.200.188.sslip.io',
  'capacitor://localhost',
  'http://localhost', 
  'https://localhost',
  'http://91.99.200.188:5000',
  'http://localhost:3000',
  'http://localhost:5173',
  'https://daaraserignemordiop.vercel.app'
];

app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || origin.startsWith('http://localhost')) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// ✅ LIMITES EXPRESS (Pour accepter les gros JSON/Body)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use('/uploads', express.static(uploadDir));

// ==========================================
// 2. CONFIGURATION UPLOAD (HYBRIDE)
// ==========================================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// A. STRATÉGIE CLOUD (Direct Cloudinary) - Pour Images, Audio, etc.
const cloudStorage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'daara-uploads',
    allowed_formats: ['jpg', 'png', 'jpeg', 'mp3', 'webp'],
    resource_type: 'auto',
  },
});
const uploadCloud = multer({ storage: cloudStorage });

// B. STRATÉGIE DISQUE (Temporaire) - SPÉCIAL LIVRES PDF 📚
// On stocke d'abord sur le serveur pour éviter les timeouts, puis on envoie à Cloudinary
const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});
const uploadDisk = multer({ 
  storage: diskStorage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB Limite Multer
});

// --- CONFIGURATION DES CHAMPS ---
// Tout le monde utilise Cloud sauf les Livres
const productUploads = uploadCloud.array('productImages', 5);
const eventUploads = uploadCloud.fields([{ name: 'eventImage', maxCount: 1 }, { name: 'eventDocument', maxCount: 1 }]);
const podcastUploads = uploadCloud.fields([{ name: 'audioFile', maxCount: 1 }, { name: 'coverImageFile', maxCount: 1 }]);
const blogUploads = uploadCloud.fields([{ name: 'coverImageFile', maxCount: 1 }, { name: 'pdfDocumentFile', maxCount: 1 }]);
const mediaUploads = uploadCloud.single('mediaFile');
const avatarUpload = uploadCloud.single('avatar');

// 🚨 CHANGEMENT: Les livres utilisent le DISQUE
const bookUploads = uploadDisk.fields([{ name: 'pdfFile', maxCount: 1 }, { name: 'coverImage', maxCount: 1 }]);


// ==========================================
// 3. MODELS & AUTH
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

// --- AUTH ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, email, password } = req.body;
    const loginKey = identifier || email;
    if (!loginKey) return res.status(400).json({ error: "Email/Tel requis" });
    const user = await User.findOne({ $or: [{ email: loginKey }, { phone: loginKey }] });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: "Identifiants incorrects" });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, identifier, password } = req.body;
    if (!identifier) return res.status(400).json({ error: "Identifiant requis" });
    const isEmail = identifier.includes('@');
    const exists = await User.findOne(isEmail ? { email: identifier } : { phone: identifier });
    if (exists) return res.status(400).json({ error: "Existe déjà" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ fullName, email: isEmail ? identifier : undefined, phone: !isEmail ? identifier : undefined, password: hashedPassword }).save();
    res.status(201).json({ message: "Compte créé" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ... (Gardez vos routes Google Auth inchangées ici) ...
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        const decodedToken = await admin.auth().verifyIdToken(token);
        const { uid, email, name, picture } = decodedToken;
        let user = await User.findOne({ $or: [{ googleId: uid }, { email }] });
        if (!user) {
            user = new User({ fullName: name, email, googleId: uid, avatar: picture, authProvider: 'google', role: 'user' });
            await user.save();
        }
        const appToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ token: appToken, user });
    } catch (err) { res.status(401).json({ error: "Auth Google échouée" }); }
});

// --- GOOGLE MOBILE ---
const googleClient = new OAuth2Client(process.env.GOOGLE_WEB_CLIENT_ID);
app.post('/api/auth/google-mobile', async (req, res) => {
  try {
    const { idToken } = req.body;
    const ticket = await googleClient.verifyIdToken({ idToken, audience: process.env.GOOGLE_WEB_CLIENT_ID });
    const { sub, email, name, picture } = ticket.getPayload();
    let user = await User.findOne({ $or: [{ googleId: sub }, { email }] });
    if (!user) {
      user = new User({ fullName: name, email, googleId: sub, avatar: picture, authProvider: 'google', role: 'user' });
      await user.save();
    }
    const appToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token: appToken, user });
  } catch (err) { res.status(401).json({ error: "Auth Mobile échouée" }); }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try { res.json(await User.findById(req.user.id).select('-password')); } catch (e) { res.status(500).json({error:e.message}); }
});

// --- BOOKS (ROUTE MODIFIÉE SPÉCIALEMENT) ---
app.get('/api/books', async (req, res) => {
    try { const books = await Book.find().sort({ createdAt: -1 }); res.json(books); } 
    catch (err) { res.status(500).json({ error: err.message }); }
});

// ✅ POST BOOKS : Upload Disque -> Cloudinary -> DB
app.post('/api/books', bookUploads, async (req, res) => {
    try {
        const pdfFile = req.files['pdfFile']?.[0];
        const coverFile = req.files['coverImage']?.[0];

        let pdfUrl = req.body.pdfUrl; // Cas où on envoie une URL
        let coverUrl = null;

        // 1. Traitement PDF (Fichier local -> Cloudinary)
        if (pdfFile) {
            console.log("📤 Uploading PDF to Cloudinary...");
            const uploadResult = await cloudinary.uploader.upload(pdfFile.path, {
                folder: 'daara/books/pdf',
                resource_type: 'auto', // Important pour PDF
                use_filename: true
            });
            pdfUrl = uploadResult.secure_url;
            // Suppression fichier local
            fs.unlinkSync(pdfFile.path); 
        }

        // 2. Traitement Cover (Fichier local -> Cloudinary)
        if (coverFile) {
            console.log("🖼️ Uploading Cover to Cloudinary...");
            const uploadResult = await cloudinary.uploader.upload(coverFile.path, {
                folder: 'daara/books/covers',
                resource_type: 'image'
            });
            coverUrl = uploadResult.secure_url;
            fs.unlinkSync(coverFile.path);
        }

        const book = new Book({
            ...req.body,
            pdfUrl: pdfUrl,
            coverUrl: coverUrl
        });

        await book.save();
        console.log("✅ Livre sauvegardé avec succès !");
        res.status(201).json(book);

    } catch (err) { 
        console.error("❌ ERREUR LIVRE:", err);
        // Nettoyage en cas d'erreur (supprimer les fichiers locaux s'ils restent)
        if (req.files?.['pdfFile']?.[0]) fs.unlinkSync(req.files['pdfFile'][0].path);
        if (req.files?.['coverImage']?.[0]) fs.unlinkSync(req.files['coverImage'][0].path);
        
        res.status(500).json({ error: err.message, details: "Upload failed" }); 
    }
});

app.delete('/api/books/:id', authenticateToken, async (req, res) => {
    try { await Book.findByIdAndDelete(req.params.id); res.json({ message: "Supprimé" }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// --- AUTRES ROUTES (Identiques à avant mais utilisant uploadCloud) ---

// PRODUCTS
app.get('/api/products', async (req, res) => {
    try { res.json(await Product.find().populate('category').sort({ createdAt: -1 })); } catch (e) { res.status(500).json({error:e.message}); }
});
app.post('/api/products', authenticateToken, productUploads, async (req, res) => {
    try {
        const imageUrls = (req.files || []).map(f => f.path);
        let { sizes, colors, ...productData } = req.body;
        if (typeof sizes === 'string') try { sizes = JSON.parse(sizes); } catch(e) { sizes = []; }
        if (typeof colors === 'string') try { colors = JSON.parse(colors); } catch(e) { colors = []; }
        const newProduct = new Product({ ...productData, sizes: sizes||[], colors: colors||[], images: imageUrls });
        await newProduct.save();
        res.status(201).json(newProduct);
    } catch (err) { res.status(400).json({ error: err.message }); }
});
app.put('/api/products/:id', authenticateToken, productUploads, async (req, res) => {
    try {
        let updateData = req.body;
        if (req.files?.length > 0) updateData.images = req.files.map(f => f.path);
        res.json(await Product.findByIdAndUpdate(req.params.id, updateData, { new: true }));
    } catch (e) { res.status(400).json({error:e.message}); }
});
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try { await Product.findByIdAndDelete(req.params.id); res.json({message:"Supprimé"}); } catch(e){ res.status(500).json({error:e.message}); }
});

// EVENTS
app.get('/api/events', async (req, res) => { try{res.json(await Event.find().sort({date:1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/events', eventUploads, async (req, res) => {
    try {
        const img = req.files['eventImage']?.[0];
        const doc = req.files['eventDocument']?.[0];
        const evt = new Event({ ...req.body, image: img?.path, documentUrl: doc?.path });
        await evt.save();
        res.status(201).json(evt);
    } catch (e) { res.status(400).json({error:e.message}); }
});
app.delete('/api/events/:id', authenticateToken, async(req,res)=>{ try{await Event.findByIdAndDelete(req.params.id);res.json({message:"OK"});}catch(e){res.status(500).json({error:e.message});} });

// PODCASTS
app.get('/api/podcasts', async(req,res)=>{ try{res.json(await Podcast.find().sort({createdAt:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/podcasts', podcastUploads, async (req, res) => {
    try {
        const audio = req.files['audioFile']?.[0];
        const cover = req.files['coverImageFile']?.[0];
        if (!audio) return res.status(400).json({error:"Audio requis"});
        const pod = new Podcast({ ...req.body, audioUrl: audio.path, coverImage: cover?.path });
        await pod.save();
        res.status(201).json(pod);
    } catch (e) { res.status(400).json({error:e.message}); }
});
app.delete('/api/podcasts/:id', authenticateToken, async(req,res)=>{ try{await Podcast.findByIdAndDelete(req.params.id);res.json({message:"OK"});}catch(e){res.status(500).json({error:e.message});} });

// BLOG
app.get('/api/blog', async(req,res)=>{ try{res.json(await BlogPost.find().sort({createdAt:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/blog', blogUploads, async (req, res) => {
    try {
        const cover = req.files['coverImageFile']?.[0];
        const pdf = req.files['pdfDocumentFile']?.[0];
        const post = new BlogPost({ ...req.body, coverImage: cover?.path, pdfDocument: pdf?.path });
        await post.save();
        res.status(201).json(post);
    } catch (e) { res.status(400).json({error:e.message}); }
});
app.put('/api/blog/:id/like', async(req,res)=>{ try{res.json(await BlogPost.findByIdAndUpdate(req.params.id,{$inc:{likes:1}},{new:true}));}catch(e){res.status(500).json({error:e.message});} });
app.delete('/api/blog/:id', authenticateToken, async(req,res)=>{ try{await BlogPost.findByIdAndDelete(req.params.id);res.json({message:"OK"});}catch(e){res.status(500).json({error:e.message});} });

// MEDIA, CONTACT, NOTIF, HOME CONTENT... (Codes standards)
app.get('/api/media', async(req,res)=>{ try{res.json(await Media.find().sort({createdAt:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/media', mediaUploads, async(req,res)=>{ try{if(!req.file)return res.status(400).json({error:"Fichier requis"}); await new Media({...req.body, url:req.file.path}).save(); res.json({message:"OK"});}catch(e){res.status(400).json({error:e.message});} });
app.delete('/api/media/:id', authenticateToken, async(req,res)=>{ try{await Media.findByIdAndDelete(req.params.id);res.json({message:"OK"});}catch(e){res.status(500).json({error:e.message});} });

app.get('/api/notifications', authenticateToken, async(req,res)=>{ try{res.json(await Notification.find().sort({date:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/notifications', authenticateToken, async(req,res)=>{ 
    try {
        const notif = new Notification(req.body);
        await notif.save();
        if(admin.apps.length) admin.messaging().send({ notification: {title:req.body.title, body:req.body.body}, topic:'all_users' }).catch(console.error);
        res.status(201).json(notif);
    } catch(e) { res.status(400).json({error:e.message}); }
});
app.delete('/api/notifications/:id', authenticateToken, async(req,res)=>{ try{await Notification.findByIdAndDelete(req.params.id);res.json({message:"OK"});}catch(e){res.status(500).json({error:e.message});} });

app.get('/api/contact', authenticateToken, async(req,res)=>{ try{res.json(await Contact.find().sort({date:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/contact', async(req,res)=>{ try{await new Contact(req.body).save(); res.json({message:"Envoyé"});}catch(e){res.status(400).json({error:e.message});} });
app.delete('/api/contact/:id', authenticateToken, async(req,res)=>{ try{await Contact.findByIdAndDelete(req.params.id);res.json({message:"Supprimé"});}catch(e){res.status(500).json({error:e.message});} });

app.get('/api/home-content', async(req,res)=>{ try{let c=await HomeContent.findOne(); res.json(c||{});}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/home-content', authenticateToken, async(req,res)=>{ try{await HomeContent.deleteMany({}); res.json(await new HomeContent(req.body).save());}catch(e){res.status(500).json({error:e.message});} });

app.post('/api/upload', authenticateToken, uploadCloud.single('file'), (req,res)=>{ if(!req.file)return res.status(400).json({error:"Manquant"}); res.json({url:req.file.path}); });

// --- ORDERS ---
app.post('/api/orders', authenticateToken, async(req,res)=>{ try{const order=new Order({...req.body, status:'Pending'}); await order.save(); res.status(201).json(order);}catch(e){res.status(400).json({error:e.message});} });
app.get('/api/orders', async(req,res)=>{ try{res.json(await Order.find().populate('user','fullName email').sort({createdAt:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.put('/api/orders/:id', authenticateToken, async(req,res)=>{ try{res.json(await Order.findByIdAndUpdate(req.params.id, {status:req.body.status}, {new:true}));}catch(e){res.status(400).json({error:"Erreur MAJ"});} });
app.delete('/api/orders/:id', authenticateToken, async(req,res)=>{ try{await Order.findByIdAndDelete(req.params.id); res.json({message:"Supprimé"});}catch(e){res.status(500).json({error:e.message});} });
app.get('/api/my-orders', authenticateToken, async(req,res)=>{ try{res.json(await Order.find({user:req.user.id}).sort({createdAt:-1}));}catch(e){res.status(500).json({error:e.message});} });

// --- USERS ---
app.get('/api/users', authenticateToken, async(req,res)=>{ try{res.json(await User.find().select('-password').sort({createdAt:-1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/users', authenticateToken, async(req,res)=>{ 
    try{
        const exists = await User.findOne({email:req.body.identifier});
        if(exists) return res.status(400).json({error:"Existe déjà"});
        const hash = await bcrypt.hash(req.body.password, 10);
        const u = new User({...req.body, password:hash});
        await u.save(); res.status(201).json(u);
    }catch(e){res.status(500).json({error:e.message});}
});
app.put('/api/users/:id', authenticateToken, async(req,res)=>{ try{res.json(await User.findByIdAndUpdate(req.params.id, req.body, {new:true}).select('-password'));}catch(e){res.status(500).json({error:e.message});} });
app.delete('/api/users/:id', authenticateToken, async(req,res)=>{ try{await User.findByIdAndDelete(req.params.id);res.json({message:"Supprimé"});}catch(e){res.status(500).json({error:e.message});} });

// --- CATEGORIES ---
app.get('/api/categories', async(req,res)=>{ try{res.json(await Category.find(req.query.type?{type:req.query.type}:{}).sort({name:1}));}catch(e){res.status(500).json({error:e.message});} });
app.post('/api/categories', authenticateToken, async(req,res)=>{ try{res.status(201).json(await new Category(req.body).save());}catch(e){res.status(400).json({error:"Erreur"});} });
app.delete('/api/categories/:id', authenticateToken, async(req,res)=>{ try{await Category.findByIdAndDelete(req.params.id);res.json({message:"OK"});}catch(e){res.status(500).json({error:e.message});} });


// ==========================================
// 5. SERVER START
// ==========================================
const MONGODB_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

// Vérification de sécurité pour éviter le crash "undefined"
if (!MONGODB_URI) {
  console.error("❌ ERREUR FATALE : La variable d'environnement MONGO_URI est manquante !");
  console.error("👉 Vérifiez vos variables dans Coolify.");
} else {
  mongoose.connect(MONGODB_URI) // ✅ CORRECTION ICI : On utilise la variable MONGODB_URI définie au-dessus
    .then(async () => {
      console.log('✅ MongoDB Connecté');
      try {
          if(!await User.findOne({email:"admin@daara.com"})) {
              await new User({fullName:"Admin", email:"admin@daara.com", password: await bcrypt.hash("password123",10), role:"admin", phone:"770000000"}).save();
              console.log("👑 Admin créé");
          }
      } catch(e) {}
    })
    .catch(e => console.log('❌ Erreur Mongo:', e));
}

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Port ${PORT}`));