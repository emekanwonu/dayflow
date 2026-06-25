const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
require('dotenv').config();

const app = express();

// ── Middleware ──
app.use(cors({ origin: process.env.CLIENT_URL || '*' }));
app.use(express.json());
app.use(morgan('dev'));

// ── DB Connection ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ──────────────────────────────────────────
// SCHEMAS
// ──────────────────────────────────────────

// User schema
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true },
  password:  { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  isActive:  { type: Boolean, default: true },
});

// Activity log schema
const activitySchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  email:     { type: String },
  action:    { type: String },
  ip:        { type: String },
  userAgent: { type: String },
  timestamp: { type: Date, default: Date.now },
  note:      { type: String },
});

// Task schema
const taskSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title:     { type: String, required: true, trim: true },
  notes:     { type: String, default: '' },
  category:  { type: String, enum: ['work','school','personal','health','other'], default: 'other' },
  priority:  { type: String, enum: ['high','medium','low'], default: 'medium' },
  completed: { type: Boolean, default: false },
  date:      { type: String },   // YYYY-MM-DD
  time:      { type: String },   // HH:MM
  order:     { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User     = mongoose.model('User', userSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Task     = mongoose.model('Task', taskSchema);

// ──────────────────────────────────────────
// HELPERS
// ──────────────────────────────────────────

const JWT_SECRET = process.env.JWT_SECRET || 'dayflow_secret_change_in_production';

function signToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
}

async function log(action, req, extra = {}) {
  try {
    await Activity.create({
      action,
      email:     extra.email  || null,
      userId:    extra.userId || null,
      ip:        getClientIP(req),
      userAgent: req.headers['user-agent'] || 'unknown',
      note:      extra.note   || null,
    });
  } catch (e) {
    console.error('Activity log error:', e.message);
  }
}

// Auth middleware
function protect(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ──────────────────────────────────────────
// AUTH ROUTES
// ──────────────────────────────────────────

// Sign up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: 'All fields are required.' });
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    const exists = await User.findOne({ email });
    if (exists) {
      await log('SIGNUP_FAILED', req, { email, note: 'Email already registered' });
      return res.status(409).json({ message: 'Email already registered.' });
    }
    const hashed = await bcrypt.hash(password, 12);
    const user   = await User.create({ name, email, password: hashed });
    await log('SIGNUP', req, { email, userId: user._id, note: 'New account created' });
    res.status(201).json({
      message: 'Account created successfully.',
      token: signToken(user),
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during signup.' });
  }
});

// Log in
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Email and password are required.' });
    const user = await User.findOne({ email });
    if (!user) {
      await log('LOGIN_FAILED', req, { email, note: 'Email not found' });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      await log('LOGIN_FAILED', req, { email, userId: user._id, note: 'Wrong password' });
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    user.lastLogin = new Date();
    await user.save();
    await log('LOGIN_SUCCESS', req, { email, userId: user._id, note: 'Successful login' });
    res.json({
      message: 'Logged in successfully.',
      token: signToken(user),
      user: { id: user._id, name: user.name, email: user.email, lastLogin: user.lastLogin },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error during login.' });
  }
});

// Get current user
app.get('/api/auth/me', protect, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found.' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ──────────────────────────────────────────
// TASK ROUTES
// ──────────────────────────────────────────

// GET all tasks for logged-in user
// Supports filters: ?category=work&priority=high&date=2026-06-23&completed=false
app.get('/api/tasks', protect, async (req, res) => {
  try {
    const filter = { userId: req.user.id };
    if (req.query.category)  filter.category  = req.query.category;
    if (req.query.priority)  filter.priority  = req.query.priority;
    if (req.query.date)      filter.date       = req.query.date;
    if (req.query.completed !== undefined) filter.completed = req.query.completed === 'true';

    const tasks = await Task.find(filter).sort({ order: 1, createdAt: -1 });
    res.json({ total: tasks.length, tasks });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// GET single task
app.get('/api/tasks/:id', protect, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user.id });
    if (!task) return res.status(404).json({ message: 'Task not found.' });
    res.json({ task });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// CREATE task
app.post('/api/tasks', protect, async (req, res) => {
  try {
    const { title, notes, category, priority, date, time } = req.body;
    if (!title) return res.status(400).json({ message: 'Task title is required.' });

    // Set order to end of list
    const count = await Task.countDocuments({ userId: req.user.id });

    const task = await Task.create({
      userId: req.user.id,
      title, notes, category, priority, date, time,
      order: count,
    });

    await log('TASK_CREATED', req, { userId: req.user.id, note: `Task: ${title}` });
    res.status(201).json({ message: 'Task created.', task });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// UPDATE task
app.put('/api/tasks/:id', protect, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user.id });
    if (!task) return res.status(404).json({ message: 'Task not found.' });

    const fields = ['title','notes','category','priority','date','time','completed','order'];
    fields.forEach(f => { if (req.body[f] !== undefined) task[f] = req.body[f]; });
    task.updatedAt = new Date();
    await task.save();

    res.json({ message: 'Task updated.', task });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// TOGGLE task complete
app.patch('/api/tasks/:id/toggle', protect, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user.id });
    if (!task) return res.status(404).json({ message: 'Task not found.' });
    task.completed = !task.completed;
    task.updatedAt = new Date();
    await task.save();
    await log('TASK_TOGGLED', req, { userId: req.user.id, note: `${task.title} → ${task.completed ? 'done' : 'undone'}` });
    res.json({ message: 'Task toggled.', task });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// REORDER tasks (drag and drop)
// Body: { orderedIds: ['id1','id2','id3',...] }
app.patch('/api/tasks/reorder', protect, async (req, res) => {
  try {
    const { orderedIds } = req.body;
    if (!Array.isArray(orderedIds))
      return res.status(400).json({ message: 'orderedIds must be an array.' });

    const updates = orderedIds.map((id, index) =>
      Task.updateOne({ _id: id, userId: req.user.id }, { order: index })
    );
    await Promise.all(updates);
    res.json({ message: 'Tasks reordered.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// DELETE task
app.delete('/api/tasks/:id', protect, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!task) return res.status(404).json({ message: 'Task not found.' });
    await log('TASK_DELETED', req, { userId: req.user.id, note: `Task: ${task.title}` });
    res.json({ message: 'Task deleted.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// DELETE all completed tasks
app.delete('/api/tasks/completed/clear', protect, async (req, res) => {
  try {
    const result = await Task.deleteMany({ userId: req.user.id, completed: true });
    res.json({ message: `${result.deletedCount} completed tasks cleared.` });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ──────────────────────────────────────────
// DASHBOARD STATS ROUTE
// ──────────────────────────────────────────

app.get('/api/dashboard/stats', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const today  = new Date().toISOString().split('T')[0];

    const [total, completed, highPriority, todayTasks, todayDone] = await Promise.all([
      Task.countDocuments({ userId }),
      Task.countDocuments({ userId, completed: true }),
      Task.countDocuments({ userId, priority: 'high', completed: false }),
      Task.countDocuments({ userId, date: today }),
      Task.countDocuments({ userId, date: today, completed: true }),
    ]);

    // Tasks by category
    const byCategory = await Task.aggregate([
      { $match: { userId: mongoose.Types.ObjectId.createFromHexString(userId) } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
    ]);

    // Tasks by priority
    const byPriority = await Task.aggregate([
      { $match: { userId: mongoose.Types.ObjectId.createFromHexString(userId) } },
      { $group: { _id: '$priority', count: { $sum: 1 } } },
    ]);

    res.json({
      total,
      completed,
      pending: total - completed,
      highPriority,
      todayTasks,
      todayDone,
      todayProgress: todayTasks ? Math.round((todayDone / todayTasks) * 100) : 0,
      byCategory,
      byPriority,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ──────────────────────────────────────────
// ADMIN / MONITORING ROUTES
// ──────────────────────────────────────────

app.get('/api/admin/activity', protect, async (req, res) => {
  try {
    const { limit = 50, action, email } = req.query;
    const filter = {};
    if (action) filter.action = action;
    if (email)  filter.email  = email;
    const logs = await Activity.find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .populate('userId', 'name email');
    res.json({ total: logs.length, logs });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/admin/stats', protect, async (req, res) => {
  try {
    const [totalUsers, totalLogins, failedLogins, signups, totalTasks, completedTasks] = await Promise.all([
      User.countDocuments(),
      Activity.countDocuments({ action: 'LOGIN_SUCCESS' }),
      Activity.countDocuments({ action: 'LOGIN_FAILED' }),
      Activity.countDocuments({ action: 'SIGNUP' }),
      Task.countDocuments(),
      Task.countDocuments({ completed: true }),
    ]);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentLogins = await Activity.countDocuments({
      action: 'LOGIN_SUCCESS',
      timestamp: { $gte: sevenDaysAgo },
    });
    res.json({ totalUsers, totalLogins, failedLogins, signups, recentLogins_last7days: recentLogins, totalTasks, completedTasks });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/admin/users', protect, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ total: users.length, users });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.get('/api/admin/users/:id/activity', protect, async (req, res) => {
  try {
    const logs = await Activity.find({ userId: req.params.id }).sort({ timestamp: -1 });
    res.json({ total: logs.length, logs });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

// ──────────────────────────────────────────
// START SERVER
// ──────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 DayFlow server running on port ${PORT}`));
