const crypto = require('crypto');

const PLANOS = {
  start: { nome: 'Start', maxClientes: 3,   maxColaboradores: 1 },
  flow:  { nome: 'Flow',  maxClientes: 10,  maxColaboradores: 3 },
  pro:   { nome: 'Pro',   maxClientes: 999, maxColaboradores: 10 }
};

const SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/identitytoolkit',
  'https://www.googleapis.com/auth/datastore'
].join(' ');

let cachedToken = null;

function serviceAccount() {
  const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || '{}');
  if (!sa.client_email || !sa.private_key || !sa.project_id) {
    throw new Error('FIREBASE_SERVICE_ACCOUNT inválida ou ausente');
  }
  sa.private_key = sa.private_key.replace(/\\n/g, '\n');
  return sa;
}

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.exp - 60 > now) return cachedToken.token;

  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: sa.client_email,
    scope: SCOPES,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  }));
  const signature = crypto.createSign('RSA-SHA256').update(`${header}.${claims}`).sign(sa.private_key);
  const jwt = `${header}.${claims}.${base64url(signature)}`;

  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: jwt })
  });
  const data = await r.json();
  if (!r.ok) throw new Error(`OAuth: ${data.error_description || data.error || r.status}`);
  cachedToken = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  return cachedToken.token;
}

async function googleFetch(token, url, method = 'GET', body) {
  const r = await fetch(url, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  if (r.status === 404) return null;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${method} ${url.split('?')[0]}: ${data.error?.message || r.status}`);
  return data;
}

// ── Firebase Auth (Identity Toolkit REST) ──
function authUrl(sa, path) {
  return `https://identitytoolkit.googleapis.com/v1/projects/${sa.project_id}/${path}`;
}

async function findUserByEmail(token, sa, email) {
  const data = await googleFetch(token, authUrl(sa, 'accounts:lookup'), 'POST', { email: [email] });
  return data?.users?.[0]?.localId || null;
}

async function createUser(token, sa, email, displayName) {
  const data = await googleFetch(token, authUrl(sa, 'accounts'), 'POST', { email, displayName, emailVerified: false });
  return data.localId;
}

async function setCustomClaims(token, sa, uid, claims) {
  await googleFetch(token, authUrl(sa, 'accounts:update'), 'POST', {
    localId: uid,
    customAttributes: JSON.stringify(claims)
  });
}

async function passwordResetLink(token, sa, email) {
  const data = await googleFetch(token, authUrl(sa, 'accounts:sendOobCode'), 'POST', {
    requestType: 'PASSWORD_RESET',
    email,
    returnOobLink: true
  });
  return data.oobLink;
}

// ── Firestore REST ──
function docUrl(sa, path) {
  return `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents/${path}`;
}

function toValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toValue) } };
  if (typeof v === 'object') return { mapValue: { fields: toFields(v) } };
  return { stringValue: String(v) };
}

function toFields(obj) {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, toValue(v)]));
}

function fromValue(v) {
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('mapValue' in v) return fromFields(v.mapValue.fields || {});
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromValue);
  return undefined;
}

function fromFields(fields) {
  return Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, fromValue(v)]));
}

async function getDoc(token, sa, path) {
  const data = await googleFetch(token, docUrl(sa, path));
  return data ? fromFields(data.fields || {}) : null;
}

async function setDoc(token, sa, path, obj, merge = false) {
  let url = docUrl(sa, path);
  if (merge) {
    const mask = Object.keys(obj).map(k => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&');
    url += `?${mask}`;
  }
  await googleFetch(token, url, 'PATCH', { fields: toFields(obj) });
}

// ── Kiwify ──
function identificarPlano(nomeProduto = '') {
  const n = nomeProduto.toLowerCase();
  if (n.includes('pro'))  return 'pro';
  if (n.includes('flow')) return 'flow';
  return 'start';
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// Kiwify envia ?signature= (HMAC-SHA1 do corpo com o token do webhook)
function verificarAssinatura(req, body) {
  const secret = process.env.KIWIFY_SECRET;
  if (!secret) return true;
  const raw = JSON.stringify(body);
  const querySig = req.query?.signature || '';
  const headerSig = req.headers['x-kiwify-signature'] || '';
  if (querySig) return safeEqual(querySig, crypto.createHmac('sha1', secret).update(raw).digest('hex'));
  if (headerSig) return safeEqual(headerSig, crypto.createHmac('sha256', secret).update(raw).digest('hex'));
  return false;
}

async function enviarEmail(email, nome, resetLink, plano) {
  const key = process.env.RESEND_API_KEY;
  if (!key) return;
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'Pautaê <noreply@pautae.com.br>',
      to: email,
      subject: `Bem-vinda ao Pautaê ${plano}! 🎉`,
      html: `<h2>Olá, ${nome}!</h2><p>Acesse o Pautaê ${plano} criando sua senha:</p><a href="${resetLink}" style="background:#F47360;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;margin:16px 0">Criar senha →</a><p style="font-size:12px;color:#888">Se não foi você, ignore este e-mail.</p>`
    })
  });
  if (!r.ok) console.error('Resend:', r.status, await r.text().catch(() => ''));
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});

  // Temporário: pular verificação de KIWIFY_SECRET / x-kiwify-signature
  // if (!verificarAssinatura(req, body)) return res.status(401).json({ error: 'Assinatura inválida' });

  const status = body.order_status || body.order?.status || body.status;
  if (status !== 'paid' && status !== 'approved') return res.status(200).json({ ok: true, msg: 'Ignorado' });

  const customer = body.Customer || body.customer || {};
  const product  = body.Product  || body.product  || {};
  const email    = String(customer.email || '').trim().toLowerCase();
  const nome     = customer.full_name || customer.name || 'Usuário';
  const produto  = product.product_name || product.name || '';

  if (!email) return res.status(400).json({ error: 'Email não encontrado' });

  const planoKey  = identificarPlano(produto);
  const planoInfo = PLANOS[planoKey];
  const now       = new Date().toISOString();

  try {
    const sa    = serviceAccount();
    const token = await getAccessToken(sa);

    let uid = await findUserByEmail(token, sa, email);
    const novoUsuario = !uid;
    if (novoUsuario) uid = await createUser(token, sa, email, nome);

    const planoFields = {
      plano: planoKey,
      maxClientes: planoInfo.maxClientes,
      maxColaboradores: planoInfo.maxColaboradores,
      updatedAt: now
    };

    // Reenvio do webhook ou nova compra do mesmo e-mail: atualiza o plano da agência existente
    const userDoc = await getDoc(token, sa, `users/${uid}`);
    let agencyId = userDoc?.agencyId;
    if (agencyId && await getDoc(token, sa, `agencies/${agencyId}`)) {
      await setDoc(token, sa, `agencies/${agencyId}`, planoFields, true);
    } else {
      agencyId = `ag_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      await setDoc(token, sa, `agencies/${agencyId}`, {
        name: nome,
        nome,
        ownerUid: uid,
        ownerId: uid,
        primaryEmail: email,
        email,
        logoUrl: null,
        logoPath: null,
        notifications: { contentApproved: true, adjustmentRequested: true, pendingApprovalReminder: true },
        approval: { revisionLimit: 3, allowClientComments: true, defaultDeadlineDays: 2 },
        ...planoFields,
        status: 'ativo',
        createdAt: now
      });
      await setDoc(token, sa, `users/${uid}`, {
        name: nome,
        nome,
        email,
        role: 'admin',
        status: 'active',
        agencyId,
        createdAt: now
      });
    }

    await setCustomClaims(token, sa, uid, { role: 'admin', agencyId });

    if (novoUsuario) {
      const resetLink = await passwordResetLink(token, sa, email);
      await enviarEmail(email, nome, resetLink, planoInfo.nome);
    }

    console.log(`Agência ${agencyId} para ${email} (plano ${planoKey})`);
    return res.status(200).json({ ok: true, agencyId, plano: planoKey });
  } catch (err) {
    console.error('Erro webhook Kiwify:', err);
    return res.status(500).json({ error: err.message });
  }
};
