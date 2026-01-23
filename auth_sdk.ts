/**
 * TypeScript Signature Verification Library
 * Synced with Go middleware logic for Chrome Extension Auth System
 * 
 * Usage in Node.js/Express:
 *   import { verifySignature, calculateSignature } from './auth_sdk';
 *   
 *   app.use((req, res, next) => {
 *     const token = req.headers.authorization?.replace('Bearer ', '');
 *     if (!verifySignature(req.method, req.url, req.body, req.headers, token)) {
 *       return res.status(403).json({ error: 'Signature verification failed' });
 *     }
 *     next();
 *   });
 */

function sortQueryString(queryParams: URLSearchParams): string {
  if (queryParams.toString() === '') return '';
  
  const sortedEntries = Array.from(queryParams.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  return sortedEntries.map(([k, v]) => `${k}=${v}`).join('&');
}

async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmacSHA256(data: string, key: string): Promise<string> {
  const keyData = new TextEncoder().encode(key);
  const msgData = new TextEncoder().encode(data);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function calculateSignature(
  method: string,
  url: string,
  body: string | Uint8Array | null,
  timestamp: string,
  tempId: string,
  token: string
): Promise<string> {
  let payload: string;
  
  if (method === 'GET') {
    const urlObj = new URL(url);
    const sortedQuery = sortQueryString(urlObj.searchParams);
    payload = `${sortedQuery}|${timestamp}|${tempId}`;
  } else {
    const bodyData = body || '';
    const bodyStr = typeof bodyData === 'string' ? bodyData : new TextDecoder().decode(bodyData);
    const bodyHash = await sha256Hex(bodyStr);
    payload = `${bodyHash}|${timestamp}|${tempId}`;
  }
  
  return hmacSHA256(payload, token);
}

export async function verifySignature(
  method: string,
  url: string,
  body: string | Uint8Array | null,
  headers: Record<string, string | undefined>,
  token: string
): Promise<boolean> {
  const clientSign = headers['x-sign'];
  const timestamp = headers['x-timestamp'];
  const tempId = headers['x-temp-id'];
  
  if (!clientSign || !timestamp || !tempId) {
    return false;
  }
  
  const serverSign = await calculateSignature(method, url, body, timestamp, tempId, token);
  
  return serverSign === clientSign;
}

export function expressSignatureMiddleware(getToken: (req: any) => string) {
  return async (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Invalid authorization header' });
    }
    
    const token = authHeader.substring(7);
    const body = req.method !== 'GET' ? JSON.stringify(req.body) : null;
    
    const isValid = await verifySignature(
      req.method,
      req.originalUrl,
      body,
      req.headers,
      token
    );
    
    if (!isValid) {
      return res.status(403).json({ error: 'Signature verification failed' });
    }
    
    next();
  };
}
