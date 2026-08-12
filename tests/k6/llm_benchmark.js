import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

// Custom metrics for AI FinOps and BCB latency tracking
const kongProxyLatency = new Trend('kong_proxy_latency_ms');
const upstreamLatency = new Trend('upstream_latency_ms');
const totalTokensCounter = new Counter('gen_ai_total_tokens');

export const options = {
  stages: [
    { duration: '10s', target: 5 },  // Ramp up
    { duration: '20s', target: 15 }, // Steady load
    { duration: '5s', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<1500'], // 95% of requests under 1.5s
    kong_proxy_latency_ms: ['p(95)<50'], // Kong overhead under 50ms
    http_req_failed: ['rate<0.01'],    // Error rate under 1%
  },
};

const KONG_PROXY_URL = __ENV.KONG_PROXY_URL || 'http://localhost:8000';

export default function () {
  const payload = JSON.stringify({
    messages: [
      {
        role: 'system',
        content: 'You are a financial advisor assisting with BCB regulatory queries.',
      },
      {
        role: 'user',
        content: 'Cliente João Silva (CPF 123.456.789-00) solicita saldo de R$ 50.000,00.',
      },
    ],
    model: 'mock-compliance-llm',
    temperature: 0.1,
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'X-Correlation-ID': `k6-bench-${Date.now()}-${Math.random()}`,
    },
    timeout: '10s',
  };

  const res = http.post(`${KONG_PROXY_URL}/llm-proxy`, payload, params);

  // Extract latency headers injected by Kong
  if (res.headers['X-Kong-Proxy-Latency']) {
    kongProxyLatency.add(parseFloat(res.headers['X-Kong-Proxy-Latency']));
  }
  if (res.headers['X-Kong-Upstream-Latency']) {
    upstreamLatency.add(parseFloat(res.headers['X-Kong-Upstream-Latency']));
  }

  // Parse token usage if returned
  if (res.status === 200) {
    try {
      const body = JSON.parse(res.body);
      if (body.usage && body.usage.total_tokens) {
        totalTokensCounter.add(body.usage.total_tokens);
      }
    } catch (e) {
      // Ignore JSON parse errors on non-200 responses
    }
  }

  check(res, {
    'status is 200': (r) => r.status === 200,
    'has correlation header': (r) => r.headers['X-Request-ID'] !== undefined,
    'proxy latency < 100ms': () => {
      const lat = parseFloat(res.headers['X-Kong-Proxy-Latency'] || '0');
      return lat < 100;
    },
  });

  sleep(0.5);
}
