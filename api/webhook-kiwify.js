// api/webhook-kiwify.js
import { initializeApp, cert, getApps } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import crypto from 'crypto';

// Inicializar Firebase Admin (só uma vez)
if (!getApps().length) {
  initializeApp({
    credential: cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))
  });
}

const PLANOS = {
  'start':  { nome: 'Start',  maxClientes: 3,   maxColaboradores: 1 },
  'flow':   { nome: 'Flow',   maxClientes: 10,  maxColaboradores: 3 },
  'pro':    { nome: 'Pro',    maxClientes: 999, maxColaboradores: 10 }
};

function identificarPlano(nomeProduto = '') {
  const nome = nomeProduto.toLowerCase();
  if (nome.includes('pro'))   return 'pro';
  if (nome.includes('flow'))  return 'flow';
  return 'start';
}

function verificarAssinatura(req, body) {
  const secret = process.env.KIWIFY_SECRET;
  if (!secret) return true; // dev: pular verificação
  const sig = req.headers['x-kiwify-signature'] || '';
  const hash = crypto.createHmac('sha256', secret)
                     .update(JSON.stringify(body))
                     .digest('hex');
  return sig === hash;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const body = req.body;

  // Verificar assinatura Kiwify
  if (!verificarAssinatura(req, body)) {
    return res.status(401).json({ error: 'Assinatura inválida' });
  }

  // Só processar compras aprovadas
  const status = body?.order?.status || body?.status;
  if (status !== 'paid' && status !== 'approved') {
    return res.status(200).json({ ok: true, msg: 'Evento ignorado' });
  }

  const email = body?.customer?.email || body?.Customer?.email;
  const nome  = body?.customer?.name  || body?.Customer?.name || 'Usuário';
  const produto = body?.product?.name || body?.Product?.name || '';

  if (!email) {
    return res.status(400).json({ error: 'Email não encontrado no payload' });
  }

  const planoKey  = identificarPlano(produto);
  const planoInfo = PLANOS[planoKey];
  const agencyId  = `ag_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;

  try {
    const auth = getAuth();
    const db   = getFirestore();

    // 1. Criar usuário no Firebase Auth (ou buscar se já existe)
    let uid;
    try {
      const user = await auth.getUserByEmail(email);
      uid = user.uid;
    } catch {
      const newUser = await auth.createUser({ email, displayName: nome });
      uid = newUser.uid;
      // Enviar email de definição de senha
      const resetLink = await auth.generatePasswordResetLink(email);
      await enviarEmailBoasVindas(email, nome, resetLink, planoInfo.nome);
    }

    // 2. Custom claim: admin da agência
    await auth.setCustomUserClaims(uid, { role: 'admin', agencyId });

    // 3. Criar documento da agência no Firestore
    await db.collection('agencies').doc(agencyId).set({
      nome:              nome,
      email:             email,
      ownerId:           uid,
      plano:             planoKey,
      maxClientes:       planoInfo.maxClientes,
      maxColaboradores:  planoInfo.maxColaboradores,
      createdAt:         new Date().toISOString(),
      status:            'ativo'
    });

    // 4. Criar documento do usuário
    await db.collection('users').doc(uid).set({
      email,
      nome,
      role:      'admin',
      agencyId,
      createdAt: new Date().toISOString()
    });

    console.log(`✅ Agência criada: ${agencyId} para ${email} (plano ${planoKey})`);
    return res.status(200).json({ ok: true, agencyId, email, plano: planoKey });

  } catch (err) {
    console.error('Erro ao criar agência:', err);
    return res.status(500).json({ error: err.message });
  }
}

async function enviarEmailBoasVindas(email, nome, resetLink, plano) {
  const RESEND_KEY = process.env.RESEND_API_KEY;
  if (!RESEND_KEY) return;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from:    'Pautaê <noreply@pautae.com.br>',
      to:      email,
      subject: `Bem-vinda ao Pautaê ${plano}! Crie sua senha 🎉`,
      html: `
        <div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:24px;color:#54283e">
          <h1 style="font-size:1.4rem;margin:0 0 12px">Olá, ${nome}! 🎉</h1>
          <p style="line-height:1.5;margin:0 0 16px">Seu acesso ao Pautaê ${plano} está pronto.</p>
          <p style="line-height:1.5;margin:0 0 20px">Clique no botão abaixo para criar sua senha e entrar na plataforma:</p>
          <p style="margin:0 0 24px">
            <a href="${resetLink}" style="display:inline-block;padding:12px 20px;background:#F47360;color:#fff;text-decoration:none;border-radius:8px;font-weight:700">
              Criar minha senha →
            </a>
          </p>
          <p style="font-size:.85rem;color:#7a6570;line-height:1.5;margin:0 0 24px">Link válido por 24h. Se não foi você, ignore este email.</p>
          <p style="font-size:.75rem;color:#9a8490;margin:0;border-top:1px solid #f5e2e6;padding-top:16px">
            Pautaê · plataforma para social medias
          </p>
        </div>
      `
    })
  });
}
