const {onCall, HttpsError} = require('firebase-functions/v2/https');
const {defineSecret} = require('firebase-functions/params');
const {initializeApp} = require('firebase-admin/app');
const {getFirestore} = require('firebase-admin/firestore');

initializeApp();
const db = getFirestore();
const anthropicApiKey = defineSecret('ANTHROPIC_API_KEY');

const MONTH_NAMES = [
  'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
  'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro',
];

function normalizeRole(role) {
  if (role === 'owner') return 'admin';
  if (role === 'viewer') return 'viewer_interno';
  return role;
}

function extractJson(text) {
  const raw = String(text || '').trim();
  if (!raw) throw new Error('Resposta vazia da IA.');
  try {
    return JSON.parse(raw);
  } catch (_) {
    const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fenced) {
      return JSON.parse(fenced[1].trim());
    }
    const start = raw.indexOf('[');
    const end = raw.lastIndexOf(']');
    if (start >= 0 && end > start) {
      return JSON.parse(raw.slice(start, end + 1));
    }
    throw new Error('Não foi possível interpretar o JSON retornado pela IA.');
  }
}

function normalizeItems(items, month) {
  if (!Array.isArray(items)) {
    throw new Error('A IA não retornou um array de conteúdos.');
  }
  const [year, mo] = month.split('-').map(Number);
  const daysInMonth = new Date(year, mo, 0).getDate();
  const allowedFormats = new Set(['feed', 'carrossel', 'reels', 'stories', 'video', 'artigo']);

  return items.map((item, idx) => {
    const titulo = String(item.titulo || item.title || `Conteúdo ${idx + 1}`).trim();
    const descricao = String(item.descricao || item.description || '').trim();
    let data = String(item.data || item.date || '').trim();
    let formato = String(item.formato || item.format || 'feed').trim().toLowerCase();

    if (formato === 'carousel') formato = 'carrossel';
    if (formato === 'reel') formato = 'reels';
    if (formato === 'story') formato = 'stories';
    if (formato === 'vídeo' || formato === 'vídeos') formato = 'video';
    if (!allowedFormats.has(formato)) formato = 'feed';

    if (!/^\d{4}-\d{2}-\d{2}$/.test(data)) {
      const day = Math.min(daysInMonth, Math.max(1, (idx % daysInMonth) + 1));
      data = `${month}-${String(day).padStart(2, '0')}`;
    } else if (!data.startsWith(month)) {
      const day = Math.min(daysInMonth, Math.max(1, Number(data.slice(-2)) || 1));
      data = `${month}-${String(day).padStart(2, '0')}`;
    }

    return {titulo, descricao, data, formato};
  }).filter((item) => item.titulo);
}

exports.generatePautaCalendar = onCall(
  {
    region: 'us-central1',
    secrets: [anthropicApiKey],
    timeoutSeconds: 120,
    memory: '512MiB',
  },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError('unauthenticated', 'Faça login para gerar o calendário.');
    }

    const text = String(request.data?.text || '').trim();
    const month = String(request.data?.month || '').trim();
    const postsPerWeek = Number(request.data?.postsPerWeek);
    const agencyId = String(request.data?.agencyId || '').trim();

    if (!text || text.length < 20) {
      throw new HttpsError('invalid-argument', 'Informe um conteúdo com pelo menos 20 caracteres.');
    }
    if (text.length > 60000) {
      throw new HttpsError('invalid-argument', 'O conteúdo é grande demais. Reduza o documento.');
    }
    if (!/^\d{4}-\d{2}$/.test(month)) {
      throw new HttpsError('invalid-argument', 'Mês inválido. Use o formato YYYY-MM.');
    }
    if (!Number.isFinite(postsPerWeek) || postsPerWeek < 1 || postsPerWeek > 21) {
      throw new HttpsError('invalid-argument', 'Informe entre 1 e 21 posts por semana.');
    }
    if (!agencyId) {
      throw new HttpsError('invalid-argument', 'Agência não informada.');
    }

    const userSnap = await db.collection('users').doc(request.auth.uid).get();
    if (!userSnap.exists) {
      throw new HttpsError('permission-denied', 'Usuário sem perfil no Postflow.');
    }
    const user = userSnap.data();
    const role = normalizeRole(user.role);
    if (user.agencyId !== agencyId || !['admin', 'collaborator'].includes(role)) {
      throw new HttpsError('permission-denied', 'Sem permissão para gerar calendário nesta agência.');
    }
    if (user.status && user.status !== 'active') {
      throw new HttpsError('permission-denied', 'Acesso removido nesta agência.');
    }

    const [year, mo] = month.split('-').map(Number);
    const monthLabel = `${MONTH_NAMES[mo - 1]} de ${year}`;
    const prompt =
      `Você é um assistente de social media. Recebi as seguintes ideias de conteúdo: ${text}. ` +
      `Distribua essas ideias em um calendário para o mês de ${monthLabel}, com ${postsPerWeek} posts por semana. ` +
      `Considere variedade de formatos — reels, carrossel, feed, stories. ` +
      `Retorne APENAS um JSON válido neste formato: ` +
      `[{"titulo":"string","descricao":"string","data":"YYYY-MM-DD","formato":"string"}]. ` +
      `Sem texto adicional, sem markdown, apenas o JSON. ` +
      `Use somente datas dentro de ${month}. ` +
      `Para formato use exatamente um destes valores: feed, carrossel, reels, stories, video, artigo.`;

    const apiKey = anthropicApiKey.value();
    if (!apiKey) {
      throw new HttpsError('failed-precondition', 'ANTHROPIC_API_KEY não configurada no servidor.');
    }

    let response;
    try {
      response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-6',
          max_tokens: 2000,
          messages: [{role: 'user', content: prompt}],
        }),
      });
    } catch (err) {
      console.error(err);
      throw new HttpsError('unavailable', 'Falha ao contatar a API do Claude.');
    }

    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      console.error('Anthropic error', response.status, payload);
      throw new HttpsError(
        'internal',
        payload?.error?.message || `Erro da Anthropic (${response.status}).`,
      );
    }

    const contentText = (payload.content || [])
      .filter((part) => part.type === 'text')
      .map((part) => part.text)
      .join('\n')
      .trim();

    try {
      const parsed = extractJson(contentText);
      const items = normalizeItems(parsed, month);
      if (!items.length) {
        throw new Error('Nenhum conteúdo gerado.');
      }
      return {items, month, postsPerWeek};
    } catch (err) {
      console.error('Parse error', err, contentText);
      throw new HttpsError('internal', err.message || 'Falha ao processar a resposta da IA.');
    }
  },
);
