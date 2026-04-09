const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// ── 방문자 추적 (IP 중복 제거) ──
const visitors = new Map(); // ip -> { date, count }
const dailyVisitors = new Map(); // date -> Set of IPs
const coupangClicks = { total: 0, daily: new Map() }; // date -> count

function getToday() {
  return new Date().toISOString().slice(0, 10);
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || req.connection.remoteAddress;
}

// ── 악성 요청 감지 ──
const blockedIPs = new Set();
const requestCounts = new Map(); // ip -> [timestamps]
const RATE_LIMIT = 100; // 1분에 100회

const sqlPatterns = /(\bSELECT\b|\bINSERT\b|\bDROP\b|\bUNION\b|--|;--|'--)/i;
const xssPatterns = /<script|javascript:|onerror=|onload=/i;

function detectMalicious(req) {
  const body = JSON.stringify(req.body || {});
  const query = JSON.stringify(req.query || {});
  const ua = req.headers['user-agent'] || '';
  
  if (sqlPatterns.test(body) || sqlPatterns.test(query)) return 'SQL Injection';
  if (xssPatterns.test(body) || xssPatterns.test(query)) return 'XSS';
  if (!ua || ua.includes('sqlmap') || ua.includes('nikto')) return 'Malicious Bot';
  return null;
}

// ── 미들웨어 ──
app.use((req, res, next) => {
  const ip = getClientIP(req);
  const today = getToday();

  // 차단된 IP
  if (blockedIPs.has(ip)) {
    return res.status(403).json({ error: 'Access denied' });
  }

  // Rate limiting
  const now = Date.now();
  const times = (requestCounts.get(ip) || []).filter(t => now - t < 60000);
  times.push(now);
  requestCounts.set(ip, times);
  if (times.length > RATE_LIMIT) {
    blockedIPs.add(ip);
    return res.status(429).json({ error: 'Too many requests' });
  }

  // 악성 요청 감지
  const threat = detectMalicious(req);
  if (threat) {
    blockedIPs.add(ip);
    console.warn(`🚨 악성 요청 감지 [${threat}] from ${ip}`);
    return res.status(403).json({ error: 'Forbidden' });
  }

  // 방문자 추적 (GET 요청만)
  if (req.method === 'GET' && req.path === '/') {
    if (!dailyVisitors.has(today)) dailyVisitors.set(today, new Set());
    dailyVisitors.get(today).add(ip);
  }

  next();
});

// ── HTML 파일 서빙 ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── OpenAI 프록시 ──
app.post('/api/generate', async (req, res) => {
  try {
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 쿠팡 클릭 추적 ──
app.post('/api/track/coupang', (req, res) => {
  const today = getToday();
  coupangClicks.total++;
  coupangClicks.daily.set(today, (coupangClicks.daily.get(today) || 0) + 1);
  res.json({ success: true });
});

// ── 통계 API (디스코드 봇용) ──
app.get('/api/stats', (req, res) => {
  const today = getToday();
  const todayVisitors = dailyVisitors.get(today)?.size || 0;
  const todayCoupang = coupangClicks.daily.get(today) || 0;

  // 최근 7일 방문자
  const weekly = {};
  for (let i = 0; i < 7; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    weekly[key] = dailyVisitors.get(key)?.size || 0;
  }

  res.json({
    today_visitors: todayVisitors,
    today_coupang_clicks: todayCoupang,
    total_coupang_clicks: coupangClicks.total,
    blocked_ips: blockedIPs.size,
    weekly_visitors: weekly,
    status: 'ok'
  });
});

// ── 보안 상태 API ──
app.get('/api/security', (req, res) => {
  res.json({
    blocked_ips: [...blockedIPs],
    blocked_count: blockedIPs.size,
    status: blockedIPs.size > 0 ? '경고' : '정상',
    issues: blockedIPs.size > 0 ? [`차단된 IP ${blockedIPs.size}개`] : []
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
