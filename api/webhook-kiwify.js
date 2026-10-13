const { initializeApp, cert, getApps } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore } = require('firebase-admin/firestore');
const crypto = require('crypto');

if (!getApps().length) {
  initializeApp({ credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
}

const PLANOS = {
  start: { nome: 'Start', maxClientes: 3, maxColaboradores: 1 },
  flow:  { nome: 'Flow',  maxClientes: 10, maxColaboradores: 3 },
  pro:   { nome: 'Pro',   maxClientes: 999, maxColaboradores: 10 }
};

function identificarPlano(nome = '') {
  const n = nome.toLowerCase();
  if (n.includes('pro'))  return 'pro';
  if (n.includes('flow')) return 'flow';
  return 'start';
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body = req.body;
  const status = body?.order?.status || body?.status;
  if (status !== 'paid' && status !== 'approved') return res.status(200).json({ ok: true, msg: 'Ignorado' });

  const email   = body?.customer?.email || body?.Customer?.email;
  const nome    = body?.customer?.name  || body?.Customer?.name || 'Usuário';
  const produto = body?.product?.name   || body?.Product?.name  || '';

  if (!email) return res.status(400).json({ error: 'Email não encontrado' });

  const planoKey  = identificarPlano(produto);
  const planoInfo = PLANOS[planoKey];
  const agencyId  = `ag_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;

  try {
    const auth = getAuth();
    const db   = getFirestore();

    let uid;
    try {
      uid = (await auth.getUserByEmail(email)).uid;
    } catch {
      uid = (await auth.createUser({ email, displayName: nome })).uid;
      const resetLink = await auth.generatePasswordResetLink(email);
      await enviarEmail(email, nome, resetLink, planoInfo.nome);
    }

    await auth.setCustomUserClaims(uid, { role: 'admin', agencyId });
    await db.collection('agencies').doc(agencyId).set({ nome, email, ownerId: uid, plano: planoKey, maxClientes: planoInfo.maxClientes, maxColaboradores: planoInfo.maxColaboradores, createdAt: new Date().toISOString(), status: 'ativo' });
    await db.collection('users').doc(uid).set({ email, nome, role: 'admin', agencyId, createdAt: new Date().toISOString() });

    return res.status(200).json({ ok: true, agencyId, email, plano: planoKey });
  } catch (err) {
    console.error('Erro:', err);
    return res.status(500).json({ error: err.message });
  }
};

async function enviarEmail(email, nome, resetLink, plano) {
  const key = process.env.RESEND_API_KEY;
  if (!key) return;
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'Pautaê <noreply@pautae.com.br>', to: email, subject: `Bem-vinda ao Pautaê ${plano}! 🎉`, html: `<h2>Olá, ${nome}!</h2><p>Acesse o Pautaê ${plano} criando sua senha:</p><a href="${resetLink}" style="background:#F47360;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;margin:16px 0">Criar senha →</a>` })
  });
}
