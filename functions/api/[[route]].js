
import { authenticate } from './auth.js';

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api/', '');
  
  try {
    // 认证检查（除了登录和注册）
    if (!['auth/login', 'auth/register'].includes(path)) {
      const authResult = await authenticate(request, env);
      if (authResult.error) {
        return new Response(JSON.stringify(authResult), { 
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      context.user = authResult.user;
    }

    // 路由分发
    switch (path) {
      case 'auth/register':
        return await handleRegister(request, env);
      case 'auth/login':
        return await handleLogin(request, env);
      case 'mindmaps':
        return await handleMindMaps(request, env, context.user);
      case 'mindmaps/share':
        return await handleShare(request, env, context.user);
      default:
        return new Response(JSON.stringify({ error: 'Not found' }), { 
          status: 404,
          headers: { 'Content-Type': 'application/json' }
        });
    }
  } catch (error) {
    console.error('API Error:', error);
    return new Response(JSON.stringify({ error: 'Internal server error' }), { 
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 用户注册
async function handleRegister(request, env) {
  const { email, username, password } = await request.json();
  
  if (!email || !username || !password) {
    return new Response(JSON.stringify({ error: 'Missing required fields' }), { 
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 检查用户是否已存在
  const existingUser = await env.DB.prepare(
    'SELECT id FROM users WHERE email = ?'
  ).bind(email).first();

  if (existingUser) {
    return new Response(JSON.stringify({ error: 'User already exists' }), { 
      status: 409,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 创建用户
  const userId = crypto.randomUUID();
  const passwordHash = await hashPassword(password);
  
  await env.DB.prepare(
    'INSERT INTO users (id, email, username, password_hash) VALUES (?, ?, ?, ?)'
  ).bind(userId, email, username, passwordHash).run();

  const token = await generateToken(userId);
  
  return new Response(JSON.stringify({ 
    token, 
    user: { id: userId, email, username } 
  }), { 
    headers: { 'Content-Type': 'application/json' }
  });
}

// 用户登录
async function handleLogin(request, env) {
  const { email, password } = await request.json();
  
  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'Missing email or password' }), { 
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 查找用户
  const user = await env.DB.prepare(
    'SELECT id, email, username, password_hash FROM users WHERE email = ?'
  ).bind(email).first();

  if (!user) {
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 验证密码
  const validPassword = await verifyPassword(password, user.password_hash);
  if (!validPassword) {
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 更新最后登录时间
  await env.DB.prepare(
    'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?'
  ).bind(user.id).run();

  const token = await generateToken(user.id);
  
  return new Response(JSON.stringify({ 
    token, 
    user: { id: user.id, email: user.email, username: user.username } 
  }), { 
    headers: { 'Content-Type': 'application/json' }
  });
}

// 思维导图 CRUD 操作
async function handleMindMaps(request, env, user) {
  const { method } = request;
  
  switch (method) {
    case 'GET':
      return await getMindMaps(env, user);
    case 'POST':
      return await createMindMap(request, env, user);
    case 'PUT':
      return await updateMindMap(request, env, user);
    case 'DELETE':
      return await deleteMindMap(request, env, user);
    default:
      return new Response(JSON.stringify({ error: 'Method not allowed' }), { 
        status: 405,
        headers: { 'Content-Type': 'application/json' }
      });
  }
}

// 获取用户的所有思维导图
async function getMindMaps(env, user) {
  const mindmaps = await env.DB.prepare(
    'SELECT id, title, created_at, updated_at, is_public FROM mindmaps WHERE user_id = ? ORDER BY updated_at DESC'
  ).bind(user.id).all();

  return new Response(JSON.stringify({ mindmaps: mindmaps.results }), { 
    headers: { 'Content-Type': 'application/json' }
  });
}

// 创建思维导图
async function createMindMap(request, env, user) {
  const { title, content } = await request.json();
  const mindmapId = crypto.randomUUID();
  
  await env.DB.prepare(
    'INSERT INTO mindmaps (id, user_id, title, content) VALUES (?, ?, ?, ?)'
  ).bind(mindmapId, user.id, title, content).run();

  return new Response(JSON.stringify({ id: mindmapId }), { 
    status: 201,
    headers: { 'Content-Type': 'application/json' }
  });
}

// 更新思维导图
async function updateMindMap(request, env, user) {
  const { id, title, content, is_public } = await request.json();
  
  const result = await env.DB.prepare(
    'UPDATE mindmaps SET title = ?, content = ?, is_public = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?'
  ).bind(title, content, is_public, id, user.id).run();

  if (result.changes === 0) {
    return new Response(JSON.stringify({ error: 'Mind map not found' }), { 
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  return new Response(JSON.stringify({ success: true }), { 
    headers: { 'Content-Type': 'application/json' }
  });
}

// 删除思维导图
async function deleteMindMap(request, env, user) {
  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  
  const result = await env.DB.prepare(
    'DELETE FROM mindmaps WHERE id = ? AND user_id = ?'
  ).bind(id, user.id).run();

  if (result.changes === 0) {
    return new Response(JSON.stringify({ error: 'Mind map not found' }), { 
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  return new Response(JSON.stringify({ success: true }), { 
    headers: { 'Content-Type': 'application/json' }
  });
}

// 分享功能
async function handleShare(request, env, user) {
  const { mindmap_id, expires_hours = 24 } = await request.json();
  
  // 验证用户拥有该思维导图
  const mindmap = await env.DB.prepare(
    'SELECT id FROM mindmaps WHERE id = ? AND user_id = ?'
  ).bind(mindmap_id, user.id).first();

  if (!mindmap) {
    return new Response(JSON.stringify({ error: 'Mind map not found' }), { 
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const shareId = crypto.randomUUID();
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + expires_hours * 60 * 60 * 1000);
  
  await env.DB.prepare(
    'INSERT INTO shares (id, mindmap_id, token, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(shareId, mindmap_id, token, expiresAt.toISOString()).run();

  return new Response(JSON.stringify({ token, expires_at: expiresAt }), { 
    headers: { 'Content-Type': 'application/json' }
  });
}

// 密码加密和验证
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}

// JWT 令牌生成和验证
async function generateToken(userId) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { userId, exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) };
  
  const base64Header = btoa(JSON.stringify(header));
  const base64Payload = btoa(JSON.stringify(payload));
  const signature = await crypto.subtle.sign(
    { name: 'HMAC' },
    await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode('your-secret-key'),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    ),
    new TextEncoder().encode(`${base64Header}.${base64Payload}`)
  );
  
  const base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${base64Header}.${base64Payload}.${base64Signature}`;
}
