'use strict';
require('dotenv').config(); 
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const multer    = require('multer');
const path      = require('path');
const fs        = require('fs');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const mongoose  = require('mongoose');
const crypto    = require('crypto');
const Razorpay  = require('razorpay');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_change_in_production';
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error("FATAL ERROR: MONGODB_URI is not defined.");
    process.exit(1);
}

// ── RAZORPAY SETUP ──
const razorpay = new Razorpay({
  key_id: 'rzp_test_SlIhRRhAA5EAa2',
  key_secret: 'CDGum0SfQGsOKon1USI26obR'
});

// ── DATABASE CONNECTION ──
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Cloud'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ── MONGODB SCHEMAS ──
const studentSchema = new mongoose.Schema({
    id: String, email: { type: String, unique: true }, passwordHash: String, appId: String, createdAt: Date
});
const Student = mongoose.model('Student', studentSchema);

const userSchema = new mongoose.Schema({
    id: String, username: { type: String, unique: true }, passwordHash: String, role: String, createdAt: Date, updatedAt: Date
});
const User = mongoose.model('User', userSchema);

const appSchema = new mongoose.Schema({
    appId: { type: String, unique: true }, status: String, step: Number,
    personal: Object, address: Object, academic: Object, documents: Object, payment: Object, declaration: Object, account: Object, adminRemarks: String, admissionNo: String, notifications: [String], submittedAt: Date, createdAt: Date, updatedAt: Date
});
const Application = mongoose.model('Application', appSchema);

const notifSchema = new mongoose.Schema({
    id: { type: String, unique: true }, title: String, body: String, type: String, priority: String, targetStatus: String, targetCategory: String, recipientCount: Number, recipientIds: [String], recipientEmails: [String], attachments: [Object], readBy: [String], sentAt: Date, isScheduled: Boolean, createdBy: String, createdAt: Date, updatedAt: Date
});
const Notification = mongoose.model('Notification', notifSchema);

const counterSchema = new mongoose.Schema({ id: String, seq: Number });
const Counter = mongoose.model('Counter', counterSchema);

// ── MIDDLEWARE ──
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return fail(res, 'No token provided', 401);
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) return fail(res, 'Failed to authenticate token', 401);
      req.user = decoded; next();
    });
};
  
const adminMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return fail(res, 'No token provided', 401);
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err || decoded.role !== 'admin') return fail(res, 'Failed to authenticate or not an admin', 401);
        req.user = decoded; next();
    });
};

// ── DIRS & SERVER CONFIG ──
const UPLOADS_DIR = path.join(__dirname, 'data', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const NOTIF_DIR = path.join(__dirname, 'data', 'notif-attachments');
fs.mkdirSync(NOTIF_DIR, { recursive: true });

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files from root folder (admin.html, etc.)
app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/api/notif-files', express.static(NOTIF_DIR));

const authLimiter   = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts. Try in 15 minutes.' } });
const uploadLimiter = rateLimit({ windowMs: 60*60*1000, max: 60, message: { error: 'Upload limit reached.' } });
const apiLimiter    = rateLimit({ windowMs: 15*60*1000, max: 300, message: { error: 'Too many requests.' } });

const now = () => new Date().toISOString();
const ok = (res, d) => res.json({ success: true, ...d });
const fail = (res, msg, code = 400) => res.status(code).json({ success: false, error: msg });
const valid = (req, res) => { const e = validationResult(req); if (!e.isEmpty()) { fail(res, e.array().map(x=>x.msg).join('; '), 422); return false; } return true; };
const safeApp = (a) => { const s = JSON.parse(JSON.stringify(a)); if (s.account) delete s.account.passwordHash; return s; };

async function generateAppId() {
    const counter = await Counter.findOneAndUpdate({ id: 'appSeq' }, { $inc: { seq: 1 } }, { new: true, upsert: true });
    return 'DYD-2026-' + String(counter.seq).padStart(5, '0');
}

// ── MULTER SETUP ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(UPLOADS_DIR, req.params.appId || 'tmp');
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => { cb(null, `${file.fieldname}-${Date.now()}${path.extname(file.originalname).toLowerCase()}`); }
});
const upload = multer({
  storage, limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const extOk = /\.(jpg|jpeg|png|pdf)$/i.test(path.extname(file.originalname));
    const mimeOk = /image\/(jpeg|png)|application\/pdf/.test(file.mimetype);
    cb(extOk && mimeOk ? null : new Error('Only JPG, PNG, PDF allowed'), extOk && mimeOk);
  }
});

const notifStorage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, NOTIF_DIR); },
    filename: (req, file, cb) => { cb(null, `notif-${Date.now()}-${Math.random().toString(36).slice(2,7)}${path.extname(file.originalname).toLowerCase()}`); }
});
const notifUpload = multer({
    storage: notifStorage, limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      const ok = /\.(jpg|jpeg|png|pdf|doc|docx|xls|xlsx|txt|zip)$/i.test(path.extname(file.originalname));
      cb(ok ? null : new Error('File type not allowed'), ok);
    }
});

// ════════ API ROUTES (Must stay above the fallback) ════════

app.post('/api/auth/register', authLimiter,
  [body('email').isEmail().normalizeEmail(), body('password').isLength({min:8}), body('appId').notEmpty()],
  async (req, res) => {
    try {
      if (!valid(req, res)) return;
      const { email, password, appId } = req.body;
      const appRecord = await Application.findOne({ appId });
      if (!appRecord) return fail(res, 'Application not found', 404);
      const existingStudent = await Student.findOne({ email });
      if (existingStudent) return fail(res, 'Email already registered', 409);
      const passwordHash = await bcrypt.hash(password, 12);
      const student = new Student({ id: uuidv4(), email, passwordHash, appId, createdAt: now() });
      await student.save();
      appRecord.account = { email }; appRecord.updatedAt = now(); await appRecord.save();
      const token = jwt.sign({ id: student.id, email, role: 'student', appId }, JWT_SECRET, { expiresIn: '7d' });
      ok(res, { token, appId });
    } catch(e) { fail(res, e.message, 500); }
  }
);

app.post('/api/auth/login', authLimiter,
  [body('email').isEmail().normalizeEmail(), body('password').notEmpty()],
  async (req, res) => {
    try {
      if (!valid(req, res)) return;
      const { email, password } = req.body;
      const s = await Student.findOne({ email });
      if (!s || !(await bcrypt.compare(password, s.passwordHash))) return fail(res, 'Invalid email or password', 401);
      const token = jwt.sign({ id: s.id, email, role: 'student', appId: s.appId }, JWT_SECRET, { expiresIn: '7d' });
      ok(res, { token, appId: s.appId });
    } catch(e) { fail(res, e.message, 500); }
  }
);

app.post('/api/auth/admin-login', authLimiter,
  [body('username').notEmpty(), body('password').notEmpty()],
  async (req, res) => {
    try {
      if (!valid(req, res)) return;
      const { username, password } = req.body;
      let admin = await User.findOne({ username });
      if (!admin && username === 'admin') {
        const hash = await bcrypt.hash('admin123', 12);
        admin = new User({ id: uuidv4(), username: 'admin', passwordHash: hash, role: 'admin', createdAt: now() });
        await admin.save();
      }
      if (!admin || !(await bcrypt.compare(password, admin.passwordHash))) return fail(res, 'Invalid credentials', 401);
      const token = jwt.sign({ id: admin.id, username, role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
      ok(res, { token, username });
    } catch(e) { fail(res, e.message, 500); }
  }
);

app.get('/api/admin/applications', adminMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)||1);
    const limit = Math.min(50, parseInt(req.query.limit)||15);
    const status = req.query.status || 'All';
    const search = (req.query.search||'').toLowerCase().trim();

    let query = {};
    if (status !== 'All') query.status = status;
    if (search) {
        query.$or = [{ appId: { $regex: search, $options: 'i' } }, { 'personal.fullName': { $regex: search, $options: 'i' } }];
    }

    const total = await Application.countDocuments(query);
    const apps = await Application.find(query).sort({ updatedAt: -1 }).skip((page - 1) * limit).limit(limit);
    
    const all = await Application.find();
    const stats = { 
      total:all.length, 
      pending:all.filter(a=>a.status==='Pending').length, 
      approved:all.filter(a=>a.status==='Approved').length, 
      rejected:all.filter(a=>a.status==='Rejected').length 
    };

    const formattedApps = apps.map(a => ({ 
      appId:a.appId, 
      status:a.status, 
      fullName:a.personal?.fullName||'—', 
      email:a.personal?.email||'—', 
      category:a.personal?.category||'—', 
      stream:a.academic?.stream||'—', 
      updatedAt:a.updatedAt 
    }));
    
    ok(res, { applications:formattedApps, total, page, stats });
  } catch(e) { fail(res, e.message, 500); }
});

// Razorpay routes
app.post('/api/applications/:appId/create-payment', authMiddleware, async (req, res) => {
    try {
        const { appId } = req.params;
        const options = { amount: 1500 * 100, currency: "INR", receipt: `rcpt_${appId}` };
        const order = await razorpay.orders.create(options);
        ok(res, { orderId: order.id, amount: order.amount });
    } catch(e) { fail(res, e.message, 500); }
});

app.post('/api/applications/:appId/verify-payment', authMiddleware, async (req, res) => {
    try {
        const { appId } = req.params;
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        const body = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSignature = crypto.createHmac("sha256", 'CDGum0SfQGsOKon1USI26obR').update(body.toString()).digest("hex");

        if (expectedSignature === razorpay_signature) {
            await Application.findOneAndUpdate({ appId }, { 'payment.status': 'Success', 'payment.txnId': razorpay_payment_id });
            ok(res, { message: 'Verified' });
        } else { fail(res, 'Invalid Signature', 400); }
    } catch(e) { fail(res, e.message, 500); }
});

// Notifications
app.get('/api/admin/notifications/stats/summary', adminMiddleware, async (req, res) => {
    try {
      const all = await Notification.find();
      ok(res, { total: all.length, totalReach: all.reduce((s, n) => s + (n.recipientCount || 0), 0) });
    } catch(e) { fail(res, e.message, 500); }
});

app.get('/api/admin/notifications', adminMiddleware, async (req, res) => {
    try {
      const notifs = await Notification.find().sort({ createdAt: -1 });
      ok(res, { notifications: notifs, total: notifs.length });
    } catch(e) { fail(res, e.message, 500); }
});

// ════════ FALLBACK ROUTE (Must be at the very bottom) ════════

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 Server live on port ${PORT}`));
