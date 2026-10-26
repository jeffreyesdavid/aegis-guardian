/*
 * Aegis Guardian: Scam Shield rules, browser edition.
 * A line-for-line port of app/scam/scam_shield.py so the scanner runs on
 * your device with no network. Keep the two in sync: app/scam/test_parity.mjs
 * checks that both give the same verdict and signals on every sample.
 */
(function (root) {
  "use strict";

  const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at"];

  const FOREIGN_CODES = ["+212", "+234", "+233", "+44 7", "+63", "+91", "+92", "+880"];

  const MONEY_WORDS = ["crypto", "bitcoin", "usdt", "gift card", "wire transfer", "cash app",
    "cashapp", "venmo", "zelle", "deposit", "activation fee", "processing fee",
    "unlock your", "withdraw your earnings",
    "tarjeta de regalo", "criptomoneda", "transferencia bancaria", "depósito",
    "cuota de activación", "tarifa de procesamiento", "retirar tus ganancias",
    "desbloquear tu"];

  const URGENCY_WORDS = ["only 20 positions", "limited slots", "act now", "offer expires",
    "today only", "last chance", "respond immediately", "within 24 hours",
    "hurry", "don't miss", "spots are filling",
    "solo hoy", "últimos lugares", "plazas limitadas", "actúa ahora",
    "responde de inmediato", "en 24 horas", "última oportunidad", "urgente"];

  const JOB_BAIT = ["recruiting team", "part-time", "remote position", "work from home",
    "daily pay", "flexible hours", "no experience", "your resume caught",
    "your impressive resume", "online reviewing", "rating tasks",
    "optimization tasks", "app testing",
    "trabajo desde casa", "medio tiempo", "sin experiencia", "pago diario",
    "horario flexible", "tu currículum", "tu curriculum", "equipo de reclutamiento"];

  const FAMILY_OPENERS = ["hi mom", "hi mum", "hi dad", "hey mom", "hey dad", "hola mamá", "hola mama",
    "hola mami", "hola papá", "hola papa", "hola hijo", "hola hija"];
  const NEW_NUMBER = ["new number", "my new phone", "lost my phone", "broke my phone", "phone broke",
    "nuevo número", "nuevo numero", "perdí mi teléfono", "se me rompió el teléfono",
    "se me rompió el celular", "mi nuevo celular"];
  const OTHER_APPS = ["whatsapp", "telegram", "signal app", "wechat", "line app"];
  const BRANDS = ["usps", "fedex", "ups ", "dhl", "irs", "amazon", "paypal", "apple id", "netflix",
    "e-zpass", "ezpass", "fastrak", "toll", "dmv", "wells fargo", "chase", "bank of america",
    "your bank", "correos", "banco", "peaje", "hacienda"];
  const BRAND_ACTIONS = ["verify", "confirm", "suspend", "locked", "unpaid", "pay now", "past due", "update your",
    "verificar", "confirmar", "suspendid", "bloquead", "pendiente de pago", "pagar", "actualiza"];
  const WRONG_NUMBER = ["wrong number", "sorry, wrong", "número equivocado", "numero equivocado", "me equivoqué de número"];

  const any = (t, words) => words.some((w) => t.includes(w));
  const count = (t, words) => words.filter((w) => t.includes(w)).length;

  const hasUrl = (t) => /https?:\/\/|www\.|\b[\w-]+\.(com|net|org|io|xyz|info|link|app)\b/.test(t);
  const replyToOtherNumber = (t) =>
    /\b(text|reply|send|message)\b[^.]{0,40}?\bto\b[^.]{0,20}?(\+?\d[\d\-\s]{6,}\d)/.test(t);
  const dailyPayRange = (t) => /\$\s?\d{2,4}\s?(?:-|to|and|y|a|–|—)\s?\$?\s?\d{2,4}/.test(t);
  const ageGate = (t) => /(no younger than|must be (?:at least|over)|aged?)\s*\d{2}/.test(t);

  // [name, weight, English why, Spanish why, test]
  const RULES = [
    ["job_bait", 25,
      "Uses unsolicited-job-offer language common in task scams",
      "Usa lenguaje de ofertas de trabajo no solicitadas, típico de estafas de tareas",
      (t) => count(t, JOB_BAIT) >= 1],
    ["job_bait_heavy", 15,
      "Multiple recruiter/task-scam phrases stacked together",
      "Junta varias frases típicas de falsos reclutadores",
      (t) => count(t, JOB_BAIT) >= 2],
    ["reply_other_number", 30,
      "Tells you to text/reply to a different number than the sender",
      "Te pide escribir o responder a un número distinto al que te envió el mensaje",
      replyToOtherNumber],
    ["fake_urgency", 20,
      "Creates false urgency ('limited spots', 'act now')",
      "Crea urgencia falsa ('plazas limitadas', 'actúa ahora')",
      (t) => count(t, URGENCY_WORDS) >= 1],
    ["too_good_pay", 20,
      "Promises high pay for little work (e.g. $200–$400/day, few hours)",
      "Promete mucho dinero por poco trabajo (por ejemplo, $200–$400 al día)",
      dailyPayRange],
    ["money_ask", 35,
      "Asks for crypto, gift cards, a money transfer, or a fee to 'unlock' or withdraw",
      "Pide cripto, tarjetas de regalo, una transferencia o una cuota para 'desbloquear' o retirar dinero",
      (t) => count(t, MONEY_WORDS) >= 1],
    ["money_ask_heavy", 15,
      "Several payment/crypto bait phrases stacked together",
      "Junta varias frases de pago o cripto",
      (t) => count(t, MONEY_WORDS) >= 2],
    ["shortened_link", 25,
      "Contains a link shortener that hides the real destination",
      "Tiene un enlace acortado que esconde a dónde te lleva de verdad",
      (t) => any(t, SHORTENERS)],
    ["foreign_code", 10,
      "Reply/contact number uses a foreign country code",
      "El número de contacto usa un código de otro país",
      (t) => FOREIGN_CODES.some((c) => t.includes(c.toLowerCase()))],
    ["age_gate", 10,
      "Adds an odd eligibility gate ('must be no younger than 25')",
      "Pone un requisito raro de edad ('debes tener al menos 25')",
      ageGate],
    ["vague_sender", 15,
      "Claims to know you ('your resume') without naming you or a real company",
      "Dice conocerte ('tu currículum') sin decir tu nombre ni el de una empresa real",
      (t) => {
        const knows = t.includes("your resume") || t.includes("your impressive resume") || t.includes("your application");
        const named = /\b(inc\.|llc|corp|company|team at)\b/.test(t);
        return knows && !named;
      }],
    ["family_impersonation", 35,
      "Pretends to be a family member texting from a 'new number'",
      "Se hace pasar por un familiar que escribe desde un 'número nuevo'",
      (t) => any(t, FAMILY_OPENERS) && any(t, NEW_NUMBER)],
    ["move_to_other_app", 15,
      "Asks you to move the chat to WhatsApp, Telegram, or another app",
      "Te pide pasar la conversación a WhatsApp, Telegram u otra app",
      (t) => any(t, OTHER_APPS)],
    ["brand_link", 30,
      "Uses a big brand or agency name plus a link asking you to verify or pay",
      "Usa el nombre de una marca o agencia con un enlace para 'verificar' o pagar",
      (t) => hasUrl(t) && any(t, BRANDS) && any(t, BRAND_ACTIONS)],
    ["wrong_number_opener", 15,
      "Opens with a 'wrong number' line, a common start to investment scams",
      "Empieza con 'número equivocado', una entrada común en estafas de inversión",
      (t) => any(t, WRONG_NUMBER)],
  ];

  function scan(message) {
    const t = String(message || "").toLowerCase();
    const signals = [];
    let score = 0;
    for (const [name, weight, why, why_es, test] of RULES) {
      if (test(t)) {
        signals.push({ name, weight, why, why_es });
        score += weight;
      }
    }
    score = Math.min(score, 100);
    const verdict = score >= 50 ? "LIKELY SCAM" : score >= 25 ? "SUSPICIOUS" : "LIKELY SAFE";
    return { verdict, score, signals };
  }

  const api = { scan, RULES };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.AegisRules = api;
})(this);
