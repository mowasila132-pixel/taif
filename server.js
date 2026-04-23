const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const Datastore = require('nedb-promises');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taif-secret-2026';

if (!fs.existsSync('./data')) fs.mkdirSync('./data');
const db = {
  users:    Datastore.create({ filename: './data/users.db',    autoload: true }),
  students: Datastore.create({ filename: './data/students.db', autoload: true }),
  sessions: Datastore.create({ filename: './data/sessions.db', autoload: true }),
};

app.use(cors()); app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(h.split(' ')[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Session expired' }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

app.get('/api/setup/status', async (req, res) => {
  const count = await db.users.count({});
  res.json({ setupRequired: count === 0 });
});
app.post('/api/setup', async (req, res) => {
  if (await db.users.count({}) > 0) return res.status(403).json({ error: 'Setup already completed.' });
  const { name, username, password, centerName } = req.body;
  if (!name || !username || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 characters' });
  const hash = await bcrypt.hash(password, 10);
  const user = await db.users.insert({ username, password: hash, name, role: 'admin', centerName: centerName||'My Center', createdAt: new Date() });
  const token = jwt.sign({ id: user._id, username: user.username, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: user._id, name: user.name, role: user.role, username: user.username } });
});
app.post('/api/login', async (req, res) => {
  const user = await db.users.findOne({ username: req.body.username });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id, username: user.username, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: user._id, name: user.name, role: user.role, username: user.username } });
});
app.get('/api/me', auth, (req, res) => res.json(req.user));
app.get('/api/users', auth, adminOnly, async (req, res) => { const u = await db.users.find({}); res.json(u.map(u=>({id:u._id,name:u.name,username:u.username,role:u.role,createdAt:u.createdAt}))); });
app.post('/api/users', auth, adminOnly, async (req, res) => {
  const { username, password, name, role } = req.body;
  if (!username||!password||!name) return res.status(400).json({ error: 'All fields required' });
  if (await db.users.findOne({ username })) return res.status(400).json({ error: 'Username exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = await db.users.insert({ username, password: hash, name, role: role||'teacher', createdAt: new Date() });
  res.json({ id: user._id, name: user.name, username: user.username, role: user.role });
});
app.delete('/api/users/:id', auth, adminOnly, async (req, res) => { await db.users.remove({ _id: req.params.id }, {}); res.json({ ok: true }); });
app.get('/api/students', auth, async (req, res) => {
  const q = req.user.role==='admin' ? {} : { teacherId: req.user.id };
  const s = await db.students.find(q).sort({ name: 1 });
  res.json(s.map(s=>({...s, id: s._id})));
});
app.post('/api/students', auth, async (req, res) => {
  if (!req.body.name) return res.status(400).json({ error: 'Name required' });
  const t = req.user.role==='admin' ? (req.body.teacherId||req.user.id) : req.user.id;
  const s = await db.students.insert({ ...req.body, teacherId: t, createdAt: new Date() });
  res.json({ ...s, id: s._id });
});
app.delete('/api/students/:id', auth, adminOnly, async (req, res) => { await db.students.remove({ _id: req.params.id }, {}); res.json({ ok: true }); });
app.get('/api/sessions', auth, async (req, res) => {
  const { studentId, limit } = req.query;
  let q = req.user.role!=='admin' ? { teacherId: req.user.id } : {};
  if (studentId) q.studentId = studentId;
  const s = await db.sessions.find(q).sort({ date: -1, createdAt: -1 });
  res.json((limit ? s.slice(0, parseInt(limit)) : s).map(s=>({...s, id:s._id})));
});
app.post('/api/sessions', auth, async (req, res) => {
  if (!req.body.studentId) return res.status(400).json({ error: 'Student required' });
  const s = await db.sessions.insert({ ...req.body, teacherId: req.user.id, createdAt: new Date() });
  res.json({ ...s, id: s._id });
});
app.delete('/api/sessions/:id', auth, async (req, res) => {
  const q = req.user.role==='admin' ? { _id: req.params.id } : { _id: req.params.id, teacherId: req.user.id };
  await db.sessions.remove(q, {}); res.json({ ok: true });
});
app.get('/api/stats', auth, async (req, res) => {
  const q = req.user.role==='admin' ? {} : { teacherId: req.user.id };
  const weekAgo = new Date(); weekAgo.setDate(weekAgo.getDate()-7);
  const [students, sessions, weekSessions, users] = await Promise.all([
    db.students.count(q), db.sessions.count(q),
    db.sessions.count({ ...q, createdAt: { $gte: weekAgo } }),
    req.user.role==='admin' ? db.users.count({}) : Promise.resolve(null),
  ]);
  res.json({ students, sessions, weekSessions, users });
});
app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`\n🌿 Taif running on port ${PORT}\n`));
