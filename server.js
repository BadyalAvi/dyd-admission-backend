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

// Serve static files from root folder (admin.html, index.html)
app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use('/api/notif-files', express.static(NOTIF_DIR));

const authLimiter   = rateLimit({ windowMs: 15*60*1000, max: 20, message: { error: 'Too many attempts. Try in 15 minutes.' } });

const now = () => new Date().toISOString();
const ok = (res, d) => res.json({ success: true, ...d });
const fail = (res, msg, code = 400) => res.status(code).json({ success: false, error: msg });
const valid = (req, res) => { const e = validationResult(req); if (!e.isEmpty()) { fail(res, e.array().map(x=>x.msg).join('; '), 422); return false; } return true; };
const safeApp = (a) => { const s = JSON.parse(JSON.stringify(a)); if (s.account) delete s.account.passwordHash; return s; };

async function generateAppId() {
    const counter = await Counter.findOneAndUpdate({ id: 'appSeq' }, { $inc: { seq: 1 } }, { new: true, upsert: true });
    return 'DYD-2026-' + String(counter.seq).padStart(5, '0');
}

// ════════ API ROUTES ════════

app.post('/api/auth/register', authLimiter, async (req, res) => {
    try {
      const { email, password, appId } = req.body;
      const appRecord = await Application.findOne({ appId });
      if (!appRecord) return fail(res, 'Application not found', 404);
      const existingStudent = await Student.findOne({ email });
      if (existingStudent) return fail(res, 'Email registered', 409);
      const passwordHash = await bcrypt.hash(password, 12);
      const student = new Student({ id: uuidv4(), email, passwordHash, appId, createdAt: now() });
      await student.save();
      appRecord.account = { email }; await appRecord.save();
      const token = jwt.sign({ id: student.id, email, role: 'student', appId }, JWT_SECRET, { expiresIn: '7d' });
      ok(res, { token, appId });
    } catch(e) { fail(res, e.message, 500); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
    try {
      const { email, password } = req.body;
      const s = await Student.findOne({ email });
      if (!s || !(await bcrypt.compare(password, s.passwordHash))) return fail(res, 'Invalid credentials', 401);
      const token = jwt.sign({ id: s.id, email, role: 'student', appId: s.appId }, JWT_SECRET, { expiresIn: '7d' });
      ok(res, { token, appId: s.appId });
    } catch(e) { fail(res, e.message, 500); }
});

app.post('/api/auth/admin-login', authLimiter, async (req, res) => {
    try {
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
});

// Admin Tracker: Get List
app.get('/api/admin/applications', adminMiddleware, async (req, res) => {
  try {
    const status = req.query.status || 'All', search = (req.query.search||'').toLowerCase().trim();
    let query = {};
    if (status !== 'All') query.status = status;
    if (search) query.$or = [{ appId: { $regex: search, $options: 'i' } }, { 'personal.fullName': { $regex: search, $options: 'i' } }];
    const apps = await Application.find(query).sort({ updatedAt: -1 });
    const all = await Application.find();
    const stats = { total:all.length, pending:all.filter(a=>a.status==='Pending').length, approved:all.filter(a=>a.status==='Approved').length, rejected:all.filter(a=>a.status==='Rejected').length };
    const formatted = apps.map(a => ({ appId:a.appId, status:a.status, fullName:a.personal?.fullName||'—', email:a.personal?.email||'—', category:a.personal?.category||'—', stream:a.academic?.stream||'—', updatedAt:a.updatedAt }));
    ok(res, { applications:formatted, stats });
  } catch(e) { fail(res, e.message, 500); }
});

// Admin Tracker: GET SINGLE APPLICATION (The fix for your error)
app.get('/api/admin/applications/:appId', adminMiddleware, async (req, res) => {
    try {
      const appRecord = await Application.findOne({ appId: req.params.appId });
      if (!appRecord) return fail(res, 'Application not found', 404);
      ok(res, { application: safeApp(appRecord) });
    } catch(e) { fail(res, e.message, 500); }
});

// Admin Tracker: Update Status/Remarks
app.patch('/api/admin/applications/:appId', adminMiddleware, async (req, res) => {
    try {
      const updates = { updatedAt: now() };
      ['status','adminRemarks','admissionNo'].forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
      const updated = await Application.findOneAndUpdate({ appId: req.params.appId }, updates, { new: true });
      if (!updated) return fail(res, 'Not found', 404);
      ok(res, { success: true });
    } catch(e) { fail(res, e.message, 500); }
});

// Student Status
app.get('/api/status/:appId', async (req, res) => {
  try {
    const appRecord = await Application.findOne({ appId: req.params.appId });
    if (!appRecord) return fail(res, 'Not found', 404);
    ok(res, { appId:appRecord.appId, status:appRecord.status, applicantName:appRecord.personal?.fullName||null, submittedAt:appRecord.submittedAt||null });
  } catch(e) { fail(res, e.message, 500); }
});

// ════════ FALLBACK ROUTE ════════

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 Live on port ${PORT}`));
