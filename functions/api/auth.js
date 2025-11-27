// auth.js - JWT 认证中间件
export async function authenticate(request, env) {
  const authHeader = request.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.substring(7);
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { error: 'Invalid token format' };
    }

    const [header, payload, signature] = parts;
    
    // 验证签名
    const secretKey = env.JWT_SECRET || 'fallback-secret-key';
    const isValid = await crypto.subtle.verify(
      { name: 'HMAC' },
      await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secretKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      ),
      Uint8Array.from(atob(signature), c => c.charCodeAt(0)),
      new TextEncoder().encode(`${header}.${payload}`)
    );

    if (!isValid) {
      return { error: 'Invalid token signature' };
    }

    // 解析payload
    const payloadData = JSON.parse(atob(payload));
    
    // 检查过期时间
    if (payloadData.exp && payloadData.exp < Math.floor(Date.now() / 1000)) {
      return { error: 'Token expired' };
    }

    // 获取用户信息
    const user = await env.DB.prepare(
      'SELECT id, email, username FROM users WHERE id = ?'
    ).bind(payloadData.userId).first();

    if (!user) {
      return { error: 'User not found' };
    }

    return { user };
  } catch (error) {
    console.error('Authentication error:', error);
    return { error: 'Invalid token' };
  }
}
