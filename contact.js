/**
 * ================================================================
 * /api/contact.js — Endpoint serverless pour le formulaire de contact
 * Compatibilité : Vercel (Edge Functions) · Netlify Functions
 *
 * SOLUTION RECOMMANDÉE : Resend (resend.com)
 * → Simple, moderne, RGPD-friendly, 3 000 emails/mois gratuits
 * → Pas de configuration SMTP Gmail complexe
 *
 * INSTALLATION :
 *   npm install resend
 *
 * VARIABLES D'ENVIRONNEMENT (dans .env ou dashboard Vercel/Netlify) :
 *   RESEND_API_KEY=re_xxxxxxxxxxxxxxxxx
 *   CONTACT_EMAIL=CONTACT@NEOTECH-SERVICE.COM
 *   SITE_URL=https://www.neotech-service.com
 *   RATE_LIMIT_WINDOW=60000     (ms — fenêtre de rate limit)
 *   RATE_LIMIT_MAX=5            (requêtes max par fenêtre)
 * ================================================================
 */

import { Resend } from 'resend';

// ================================================================
// CONFIGURATION
// ================================================================
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const CONTACT_EMAIL  = process.env.CONTACT_EMAIL  || 'CONTACT@NEOTECH-SERVICES.COM';
const FROM_EMAIL     = process.env.FROM_EMAIL      || 'noreply@neotech-services.com';
const SITE_URL       = process.env.SITE_URL        || 'https://www.neotech-service.com';

// Rate limiting en mémoire (remplacer par Redis sur production haute charge)
const rateLimitStore = new Map();
const RATE_WINDOW = Number(process.env.RATE_LIMIT_WINDOW) || 60_000; // 1 min
const RATE_MAX    = Number(process.env.RATE_LIMIT_MAX)    || 5;

// ================================================================
// UTILITAIRES
// ================================================================

/**
 * Sanitisation — supprime les caractères dangereux
 */
function sanitize(value) {
  if (typeof value !== 'string') return '';
  return value
    .trim()
    .replace(/[<>]/g, '')           // XSS basique
    .replace(/[\r\n\t]/g, ' ')      // Injection headers
    .substring(0, 2000);            // Limite la longueur
}

/**
 * Validation email RFC 5322 simplifiée
 */
function isValidEmail(email) {
  return /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(email);
}

/**
 * Validation téléphone (optionnel)
 */
function isValidPhone(tel) {
  if (!tel || tel.length === 0) return true;
  return /^[\d\s\+\-\.\(\)]{6,20}$/.test(tel);
}

/**
 * Rate limiting par IP
 */
function checkRateLimit(ip) {
  const now = Date.now();
  const key = ip || 'unknown';

  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, { count: 1, reset: now + RATE_WINDOW });
    return { ok: true };
  }

  const record = rateLimitStore.get(key);

  if (now > record.reset) {
    rateLimitStore.set(key, { count: 1, reset: now + RATE_WINDOW });
    return { ok: true };
  }

  if (record.count >= RATE_MAX) {
    return {
      ok: false,
      retryAfter: Math.ceil((record.reset - now) / 1000)
    };
  }

  record.count++;
  return { ok: true };
}

/**
 * Vérifie le honeypot anti-bot
 */
function isBot(body) {
  return body.website && body.website.length > 0;
}

/**
 * Headers de sécurité
 */
function securityHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}

/**
 * Template HTML email entrant (vers NeoTech)
 */
function buildAdminEmail(data) {
  const serviceLabels = {
    maintenance: 'Maintenance & Support IT',
    cybersecurite: 'Cybersécurité',
    cloud: 'Cloud & Infrastructure',
    developpement: 'Développement Web',
    supervision: 'Supervision & Monitoring',
    conseil: 'Conseil & Audit IT',
    autre: 'Autre demande',
  };
  const serviceLabel = serviceLabels[data.service] || data.service;

  return `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nouveau message — NeoTech Service</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0a0f1e,#1a2236);padding:32px 40px;text-align:center">
              <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700">
                🔔 Nouveau message de contact
              </h1>
              <p style="margin:8px 0 0;color:#94a3b8;font-size:14px">NeoTech Service — Formulaire de contact</p>
            </td>
          </tr>

          <!-- Badge service -->
          <tr>
            <td style="padding:24px 40px 0;text-align:center">
              <span style="display:inline-block;background:#e0f7ff;color:#0077aa;padding:6px 16px;border-radius:100px;font-size:13px;font-weight:600">
                ${serviceLabel}
              </span>
            </td>
          </tr>

          <!-- Corps -->
          <tr>
            <td style="padding:24px 40px">

              <!-- Infos contact -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border-radius:8px;margin-bottom:20px">
                <tr>
                  <td style="padding:20px 24px">
                    <h2 style="margin:0 0 16px;font-size:15px;color:#374151;font-weight:700;text-transform:uppercase;letter-spacing:.06em">Coordonnées</h2>
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="padding:6px 0;color:#6b7280;font-size:14px;width:120px">Nom complet</td>
                        <td style="padding:6px 0;color:#111827;font-weight:600;font-size:14px">${sanitize(data.prenom)} ${sanitize(data.nom)}</td>
                      </tr>
                      ${data.societe ? `
                      <tr>
                        <td style="padding:6px 0;color:#6b7280;font-size:14px">Société</td>
                        <td style="padding:6px 0;color:#111827;font-weight:600;font-size:14px">${sanitize(data.societe)}</td>
                      </tr>` : ''}
                      <tr>
                        <td style="padding:6px 0;color:#6b7280;font-size:14px">Email</td>
                        <td style="padding:6px 0;font-size:14px">
                          <a href="mailto:${sanitize(data.email)}" style="color:#0077aa;text-decoration:none;font-weight:600">${sanitize(data.email)}</a>
                        </td>
                      </tr>
                      ${data.telephone ? `
                      <tr>
                        <td style="padding:6px 0;color:#6b7280;font-size:14px">Téléphone</td>
                        <td style="padding:6px 0;font-size:14px">
                          <a href="tel:${sanitize(data.telephone)}" style="color:#0077aa;text-decoration:none;font-weight:600">${sanitize(data.telephone)}</a>
                        </td>
                      </tr>` : ''}
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Message -->
              <h2 style="margin:0 0 12px;font-size:15px;color:#374151;font-weight:700;text-transform:uppercase;letter-spacing:.06em">Message</h2>
              <div style="background:#f8fafc;border-left:4px solid #00d4ff;border-radius:0 8px 8px 0;padding:20px 24px;color:#374151;font-size:15px;line-height:1.7;white-space:pre-wrap">${sanitize(data.message)}</div>

              <!-- CTA Répondre -->
              <div style="text-align:center;margin-top:28px">
                <a href="mailto:${sanitize(data.email)}?subject=Re: Votre demande ${serviceLabel} — NeoTech Service"
                  style="display:inline-block;background:linear-gradient(135deg,#00d4ff,#7c3aed);color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px">
                  ↩ Répondre à ${sanitize(data.prenom)}
                </a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb">
              <p style="margin:0;color:#9ca3af;font-size:12px">
                Message reçu le ${new Date(data.timestamp).toLocaleString('fr-FR', { timeZone: 'Europe/Paris' })} ·
                IP: ${sanitize(data._ip || 'N/A')} ·
                <a href="${SITE_URL}" style="color:#9ca3af">${SITE_URL}</a>
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

/**
 * Template HTML email de confirmation (vers l'expéditeur)
 */
function buildConfirmEmail(data) {
  return `
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Confirmation de votre message — NeoTech Service</title>
</head>
<body style="margin:0;padding:0;background:#f0f4f8;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08)">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0a0f1e,#1a2236);padding:32px 40px;text-align:center">
              <div style="width:60px;height:60px;background:linear-gradient(135deg,#00d4ff,#7c3aed);border-radius:14px;margin:0 auto 16px;display:flex;align-items:center;justify-content:center">
                <span style="font-size:28px">✓</span>
              </div>
              <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700">Message bien reçu !</h1>
              <p style="margin:8px 0 0;color:#94a3b8;font-size:14px">Nous vous répondrons sous 24h ouvrées</p>
            </td>
          </tr>

          <!-- Corps -->
          <tr>
            <td style="padding:36px 40px">
              <p style="margin:0 0 20px;color:#374151;font-size:16px;line-height:1.7">
                Bonjour <strong>${sanitize(data.prenom)}</strong>,
              </p>
              <p style="margin:0 0 20px;color:#374151;font-size:15px;line-height:1.7">
                Merci de nous avoir contactés. Votre demande concernant <strong>${sanitize(data.service)}</strong> a bien été enregistrée.
              </p>
              <p style="margin:0 0 28px;color:#374151;font-size:15px;line-height:1.7">
                Un membre de notre équipe vous répondra <strong>dans les 24 heures ouvrées</strong>.
                Pour toute urgence, vous pouvez nous appeler directement.
              </p>

              <!-- Rappel du message -->
              <div style="background:#f8fafc;border-radius:8px;padding:20px 24px;margin-bottom:28px">
                <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.08em">Votre message</p>
                <p style="margin:0;color:#6b7280;font-size:14px;line-height:1.6;white-space:pre-wrap">${sanitize(data.message).substring(0, 300)}${data.message.length > 300 ? '...' : ''}</p>
              </div>

              <!-- Contact direct -->
              <div style="background:#e0f7ff;border-radius:8px;padding:20px 24px;margin-bottom:28px;text-align:center">
                <p style="margin:0 0 4px;color:#0077aa;font-size:13px;font-weight:600">Urgence ? Contactez-nous directement</p>
                <a href="mailto:${CONTACT_EMAIL}" style="color:#0077aa;font-weight:700;font-size:15px;text-decoration:none">${CONTACT_EMAIL}</a>
              </div>

              <div style="text-align:center">
                <a href="${SITE_URL}"
                  style="display:inline-block;background:linear-gradient(135deg,#00d4ff,#7c3aed);color:#ffffff;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px">
                  Visiter notre site
                </a>
              </div>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;padding:20px 40px;text-align:center;border-top:1px solid #e5e7eb">
              <p style="margin:0 0 4px;color:#9ca3af;font-size:12px">
                © ${new Date().getFullYear()} NeoTech Service · Annecy, Haute-Savoie
              </p>
              <p style="margin:0;color:#9ca3af;font-size:12px">
                Vous recevez cet email car vous nous avez contactés via notre formulaire.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ================================================================
// HANDLER PRINCIPAL (Vercel Edge Function)
// ================================================================
export default async function handler(req, res) {

  // Sécurité : méthode uniquement POST
  if (req.method !== 'POST') {
    return res.status(405)
      .setHeaders(securityHeaders())
      .json({ error: 'Méthode non autorisée' });
  }

  // CORS : refuser les origines non autorisées
  const origin = req.headers.origin || '';
  const allowedOrigins = [SITE_URL, 'http://localhost:3000', 'http://localhost:8080'];
  if (!allowedOrigins.includes(origin) && process.env.NODE_ENV === 'production') {
    return res.status(403)
      .setHeaders(securityHeaders())
      .json({ error: 'Origine non autorisée' });
  }

  // Headers de sécurité
  Object.entries(securityHeaders()).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With');

  // Rate limiting par IP
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
  const rl = checkRateLimit(ip);
  if (!rl.ok) {
    res.setHeader('Retry-After', String(rl.retryAfter));
    return res.status(429).json({
      error: `Trop de requêtes. Réessayez dans ${rl.retryAfter} secondes.`
    });
  }

  // Parse body
  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

  // ---- VALIDATIONS ----

  // Honeypot
  if (isBot(body)) {
    // Retourner 200 pour ne pas alerter le bot
    return res.status(200).json({ ok: true });
  }

  // Vérification du token X-Requested-With (protection CSRF simple)
  if (!req.headers['x-requested-with']) {
    return res.status(403).json({ error: 'Requête non autorisée' });
  }

  // Validation des champs requis
  const { prenom, nom, email, telephone, societe, service, message, timestamp } = body;

  if (!prenom || !nom || !email || !service || !message) {
    return res.status(400).json({ error: 'Tous les champs requis doivent être remplis.' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Adresse email invalide.' });
  }

  if (!isValidPhone(telephone)) {
    return res.status(400).json({ error: 'Numéro de téléphone invalide.' });
  }

  if (message.trim().length < 20 || message.length > 5000) {
    return res.status(400).json({ error: 'Le message doit contenir entre 20 et 5000 caractères.' });
  }

  // Vérification âge du timestamp (évite les replays trop anciens)
  const ts = new Date(timestamp).getTime();
  if (isNaN(ts) || Math.abs(Date.now() - ts) > 3_600_000) {
    return res.status(400).json({ error: 'Requête expirée. Rechargez la page.' });
  }

  // ---- ENVOI EMAIL ----
  if (!RESEND_API_KEY) {
    console.error('RESEND_API_KEY manquant');
    return res.status(500).json({ error: 'Configuration serveur incomplète.' });
  }

  const resend = new Resend(RESEND_API_KEY);
  const enrichedData = { ...body, _ip: ip };

  try {
    // Email 1 : notification à NeoTech Service
    const adminResult = await resend.emails.send({
      from: `NeoTech Contact <${FROM_EMAIL}>`,
      to: [CONTACT_EMAIL],
      replyTo: email.toLowerCase(),
      subject: `[NeoTech] Nouveau message de ${sanitize(prenom)} ${sanitize(nom)} — ${sanitize(service)}`,
      html: buildAdminEmail(enrichedData),
      tags: [
        { name: 'category', value: 'contact-form' },
        { name: 'service', value: sanitize(service) },
      ],
    });

    if (adminResult.error) throw new Error(adminResult.error.message);

    // Email 2 : confirmation automatique à l'expéditeur
    await resend.emails.send({
      from: `NeoTech Service <${FROM_EMAIL}>`,
      to: [email.toLowerCase()],
      subject: `✓ Votre message a bien été reçu — NeoTech Service`,
      html: buildConfirmEmail(enrichedData),
    }).catch(err => {
      // Non bloquant : si la confirmation échoue, l'envoi principal a réussi
      console.warn('Email de confirmation échoué:', err.message);
    });

    return res.status(200).json({
      ok: true,
      message: 'Votre message a été envoyé avec succès.',
    });

  } catch (err) {
    console.error('Erreur Resend:', err);
    return res.status(500).json({
      error: 'Impossible d\'envoyer le message. Réessayez ou contactez-nous directement.',
    });
  }
}
