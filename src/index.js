import { MongoClient } from 'mongodb';

let cachedClient = null;

async function getClient(uri) {
  if (cachedClient) return cachedClient;
  const client = new MongoClient(uri, { maxPoolSize: 1, serverSelectionTimeoutMS: 10000 });
  await client.connect();
  cachedClient = client;
  return client;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}

async function hash(pw) {
  const data = new TextEncoder().encode(pw);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function verifyToken(request) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  return auth.split(' ')[1];
}

function generateKey(prefix = 'HQCRX') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = prefix + '-';
  for (let i = 0; i < 12; i++) {
    if (i > 0 && i % 4 === 0) key += '-';
    key += chars[Math.floor(Math.random() * chars.length)];
  }
  return key;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
    }

    try {
      const client = await getClient(env.MONGODB_URI);
      const db = client.db('fox_store');
      const users = db.collection('users');
      const keys = db.collection('keys');
      const mods = db.collection('mods');
      const packages = db.collection('packages');
      const auditLogs = db.collection('auditLogs');
      const transactions = db.collection('transactions');

      if (path === '/api/admin/auth/login' && method === 'POST') {
        const { username, password } = await request.json();
        const user = await users.findOne({ username });
        if (!user || user.password !== await hash(password)) return json({ ok: false, error: 'Invalid credentials' }, 401);
        if (!user.isActive) return json({ ok: false, error: 'Account disabled' }, 403);
        const token = btoa(`${user.username}:${Date.now()}`);
        await users.updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date() } });
        await auditLogs.insertOne({ action: 'login_success', adminId: user._id, createdAt: new Date() });
        return json({ ok: true, token, user: { username: user.username, role: user.role } });
      }

      if (path === '/api/admin/auth/me' && method === 'GET') {
        const token = verifyToken(request);
        if (!token) return json({ ok: false, error: 'Unauthorized' }, 401);
        const username = atob(token).split(':')[0];
        const user = await users.findOne({ username });
        if (!user) return json({ ok: false, error: 'User not found' }, 404);
        const balance = (await transactions.aggregate([{ $match: { userId: user._id } }, { $group: { _id: null, total: { $sum: '$amount' } } }]).toArray())[0]?.total || 0;
        return json({ ok: true, user, wallet: { balance, currency: 'BDT' } });
      }

      if (path === '/api/admin/mods' && method === 'GET') {
        const allMods = await mods.find({}).toArray();
        return json({ ok: true, data: allMods });
      }

      if (path === '/api/admin/mods' && method === 'POST') {
        const body = await request.json();
        const newMod = { ...body, isActive: true, createdAt: new Date() };
        await mods.insertOne(newMod);
        return json({ ok: true, data: newMod });
      }

      if (path === '/api/admin/packages' && method === 'GET') {
        const allPkgs = await packages.find({}).toArray();
        return json({ ok: true, data: allPkgs });
      }

      if (path === '/api/admin/packages' && method === 'POST') {
        const body = await request.json();
        const newPkg = { ...body, isActive: true, createdAt: new Date() };
        await packages.insertOne(newPkg);
        return json({ ok: true, data: newPkg });
      }

      if (path === '/api/admin/keys' && method === 'GET') {
        const page = parseInt(url.searchParams.get('page') || '1');
        const pageSize = parseInt(url.searchParams.get('pageSize') || '24');
        const allKeys = await keys.find({}).skip((page - 1) * pageSize).limit(pageSize).toArray();
        const total = await keys.countDocuments();
        return json({ ok: true, data: allKeys, pagination: { total, totalPages: Math.ceil(total / pageSize), page, pageSize } });
      }

      if (path === '/api/admin/keys' && method === 'POST') {
        const { count = 1, keyPrefix = 'HQCRX', keyType = 'regular', access = 1, packageId = null } = await request.json();
        const newKeys = [];
        for (let i = 0; i < count; i++) {
          const keyString = generateKey(keyPrefix);
          const newKey = { key: keyString, status: 'active', keyType, access, usedCount: 0, packageId, createdAt: new Date(), expiresAt: keyType === 'regular' ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : null };
          await keys.insertOne(newKey);
          newKeys.push(newKey);
        }
        return json({ ok: true, data: newKeys });
      }

      if (path === '/api/admin/resellers' && method === 'GET') {
        const allResellers = await users.find({ role: { $ne: 'ruler' } }).toArray();
        return json({ ok: true, data: allResellers });
      }

      if (path === '/api/admin/resellers' && method === 'POST') {
        const body = await request.json();
        const newUser = { username: body.username, password: await hash(body.password), role: 'reseller', isActive: true, balance: 0, discountPercent: 0, createdAt: new Date() };
        await users.insertOne(newUser);
        return json({ ok: true, data: newUser });
      }

      if (path === '/api/admin/audit' && method === 'GET') {
        const page = parseInt(url.searchParams.get('page') || '1');
        const pageSize = parseInt(url.searchParams.get('pageSize') || '50');
        const logs = await auditLogs.find({}).sort({ createdAt: -1 }).skip((page - 1) * pageSize).limit(pageSize).toArray();
        const total = await auditLogs.countDocuments();
        return json({ ok: true, data: logs, pagination: { total, totalPages: Math.ceil(total / pageSize), page, pageSize } });
      }

      return json({ ok: false, error: 'Route not found' }, 404);
    } catch (error) {
      return json({ ok: false, error: error.message }, 500);
    }
  }
};
