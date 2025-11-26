
export async function authenticate(request, env) {
  const authHeader = request.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { error: 'Missing or invalid authorization header' };
  }

  const token = authHeader.slice(7);
  
  try {
    const [header, payload, signature] = token.split('.');
    
    // 验证签名
    const isValid = await crypto.subtle.verify(
      { name: 'HMAC' },
      await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode('your-secret-key'),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      ),
      new Uint8Array([...atob(signature)].map(c => c.charCodeAt(0))),
      new TextEncoder().encode(`${header}.${payload}`)
    );

    if (!isValid) {
      return { error: 'Invalid token signature' };
    }

    const payloadData = JSON.parse(atob(payload));
    
    // 检查令牌是否过期
    if (payloadData.exp < Math.floor(Date.now() / 1000)) {
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
    return { error: 'Invalid token' };
  }
}
