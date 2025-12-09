import { generateClientId, encryptMessage, decryptMessage, logEvent, isString, isObject, getTime, hashPassword, verifyPassword, generateNonce, encryptAES, decryptAES } from './utils.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 处理WebSocket请求
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader === 'websocket') {
      // 新增：验证Origin（生产环境建议严格限制）
      const origin = request.headers.get('Origin');
      if (!this.isValidOrigin(origin, env.ALLOWED_ORIGINS)) {
        return new Response('Unauthorized Origin', { status: 403 });
      }
      
      const id = env.CHAT_ROOM.idFromName('chat-room');
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request);
    }

    // 处理API请求
    if (url.pathname.startsWith('/api/')) {
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    }

    // 其余全部交给 ASSETS 处理
    return env.ASSETS.fetch(request);
  },
  
  // 验证请求来源
  isValidOrigin(origin, allowedOrigins) {
    if (!origin) return false;
    if (!allowedOrigins) return true; // 未配置则允许所有（不推荐）
    const allowed = allowedOrigins.split(',');
    return allowed.some(allowedOrigin => origin === allowedOrigin || 
      (allowedOrigin.endsWith('*') && origin.startsWith(allowedOrigin.slice(0, -1))));
  }
};

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.clients = {};
    this.channels = {};
    this.config = {
      seenTimeout: 30000, // 缩短超时时间至30秒
      maxMessageSize: 2 * 1024 * 1024, // 限制消息大小为2MB
      authTimeout: 15000, // 验证超时15秒
      debug: false
    };
    this.initRSAKeyPair();
    
    // 安全增强：使用哈希存储密码，支持多用户
    this.credentials = new Map();
    this.loadCredentials(env);
    
    // 存储验证状态和临时数据
    this.authenticatedClients = new Set();
    this.authNonces = new Map(); // 存储验证用nonce
  }
  
  // 加载用户凭证（从环境变量）
  async loadCredentials(env) {
    if (env.USER_CREDENTIALS) {
      try {
        const creds = JSON.parse(env.USER_CREDENTIALS);
        for (const [username, hash] of Object.entries(creds)) {
          this.credentials.set(username, hash);
        }
      } catch (e) {
        console.error('Failed to load credentials:', e);
      }
    }
  }

  async initRSAKeyPair() {
    try {
      let stored = await this.state.storage.get('rsaKeyPair');
      if (!stored) {
        console.log('Generating new RSA keypair...');
        const keyPair = await crypto.subtle.generateKey(
          {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 4096, // 增强：使用4096位密钥
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-512' // 增强：使用SHA-512
          },
          true,
          ['sign', 'verify']
        );

        const [publicKeyBuffer, privateKeyBuffer] = await Promise.all([
          crypto.subtle.exportKey('spki', keyPair.publicKey),
          crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
        ]);
        
        stored = {
          rsaPublic: btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer))),
          rsaPrivateData: Array.from(new Uint8Array(privateKeyBuffer)),
          createdAt: Date.now(),
          rotationCount: 0 // 新增：密钥轮换计数
        };
        
        await this.state.storage.put('rsaKeyPair', stored);
        console.log('RSA key pair generated and stored');
      }
      
      if (stored.rsaPrivateData) {
        const privateKeyBuffer = new Uint8Array(stored.rsaPrivateData);
        
        stored.rsaPrivate = await crypto.subtle.importKey(
          'pkcs8',
          privateKeyBuffer,
          {
            name: 'RSASSA-PKCS1-v1_5',
            hash: 'SHA-512'
          },
          false,
          ['sign']
        );
      }
      this.keyPair = stored;
      
      // 增强：缩短密钥轮换时间至12小时
      if (stored.createdAt && (Date.now() - stored.createdAt > 12 * 60 * 60 * 1000)) {
        if (Object.keys(this.clients).length === 0) {
          console.log('密钥已使用12小时，进行轮换...');
          await this.state.storage.delete('rsaKeyPair');
          this.keyPair = null;
          await this.initRSAKeyPair();
        } else {
          await this.state.storage.put('pendingKeyRotation', true);
        }
      }
    } catch (error) {
      console.error('Error initializing RSA key pair:', error);
      throw error;
    }
  }

  async fetch(request) {
    const upgradeHeader = request.headers.get('Upgrade');
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected WebSocket Upgrade', { status: 426 });
    }

    if (!this.keyPair) {
      await this.initRSAKeyPair();
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);

    this.handleSession(server);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  async handleSession(connection) {
    connection.accept();
    await this.cleanupOldConnections();
    const clientId = generateClientId();

    if (!clientId || this.clients[clientId]) {
      this.closeConnection(connection, 4001, 'Invalid client ID');
      return;
    }

    logEvent('connection', clientId, 'debug');
    this.clients[clientId] = {
      connection: connection,
      seen: getTime(),
      key: null,
      shared: null,
      channel: null,
      username: null, // 新增：存储用户名
      authExpires: getTime() + this.config.authTimeout // 验证超时时间
    };

    // 安全增强：使用nonce防止重放攻击
    const nonce = generateNonce();
    this.authNonces.set(clientId, nonce);
    
    // 发送验证请求（包含nonce）
    this.sendMessage(connection, JSON.stringify({
      type: 'auth-required',
      nonce: nonce,
      message: '请输入用户名和密码进行验证'
    }));

    // 新增：验证超时处理
    const authTimeout = setTimeout(() => {
      if (!this.authenticatedClients.has(clientId)) {
        this.closeConnection(connection, 4401, 'Authentication timeout');
        this.cleanupClient(clientId);
      }
    }, this.config.authTimeout);

    connection.addEventListener('message', async (event) => {
      const message = event.data;

      if (!isString(message) || !this.clients[clientId]) {
        return;
      }

      this.clients[clientId].seen = getTime();

      // 未验证客户端只处理验证消息
      if (!this.authenticatedClients.has(clientId)) {
        this.handleAuthMessage(clientId, message, connection);
        return;
      }

      if (message === 'ping') {
        this.sendMessage(connection, 'pong');
        return;
      }

      logEvent('message', [clientId, message], 'debug');

      // 增强：严格限制消息大小
      if (message.length > this.config.maxMessageSize) {
        this.sendMessage(connection, JSON.stringify({
          type: 'error',
          message: 'Message too large'
        }));
        return;
      }

      if (!this.clients[clientId].shared && message.length < 2048) {
        try {
          const keys = await crypto.subtle.generateKey(
            {
              name: 'ECDH',
              namedCurve: 'P-521' // 增强：使用更安全的P-521曲线
            },
            true,
            ['deriveBits', 'deriveKey']
          );

          const publicKeyBuffer = await crypto.subtle.exportKey('raw', keys.publicKey);
          
          const signature = await crypto.subtle.sign(
            {
              name: 'RSASSA-PKCS1-v1_5'
            },
            this.keyPair.rsaPrivate,
            publicKeyBuffer
          );

          // 增强：验证客户端公钥格式
          if (!/^[0-9a-fA-F]+$/.test(message)) {
            throw new Error('Invalid public key format');
          }
          
          const clientPublicKeyHex = message;
          const clientPublicKeyBytes = new Uint8Array(clientPublicKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
          
          // 增强：验证公钥长度
          if (clientPublicKeyBytes.length !== 65) { // P-521公钥长度固定
            throw new Error('Invalid public key length');
          }
          
          const clientPublicKey = await crypto.subtle.importKey(
            'raw',
            clientPublicKeyBytes,
            { name: 'ECDH', namedCurve: 'P-521' },
            false,
            []
          );

          const sharedSecretBits = await crypto.subtle.deriveBits(
            {
              name: 'ECDH',
              public: clientPublicKey
            },
            keys.privateKey,
            521 // P-521对应521位
          );
          
          // 增强：使用HKDF派生密钥而非简单切片
          const hkdfParams = {
            name: 'HKDF',
            salt: crypto.getRandomValues(new Uint8Array(32)),
            info: new TextEncoder().encode('chat-app-shared-secret'),
            hash: 'SHA-256'
          };
          
          const hkdfKey = await crypto.subtle.importKey(
            'raw',
            sharedSecretBits,
            { name: 'HKDF' },
            false,
            ['deriveBits']
          );
          
          // 派生32字节AES密钥
          const derivedBits = await crypto.subtle.deriveBits(
            hkdfParams,
            hkdfKey,
            256
          );
          
          this.clients[clientId].shared = new Uint8Array(derivedBits);
          this.clients[clientId].hkdfSalt = Array.from(hkdfParams.salt); // 存储salt用于验证

          const response = Array.from(new Uint8Array(publicKeyBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('') + 
            '|' + btoa(String.fromCharCode(...new Uint8Array(signature))) +
            '|' + btoa(String.fromCharCode(...hkdfParams.salt)); // 包含salt
            
          this.sendMessage(connection, response);

        } catch (error) {
          logEvent('message-key', [clientId, error], 'error');
          this.closeConnection(connection, 4002, 'Key exchange failed');
        }

        return;
      }

      if (this.clients[clientId].shared) {
        this.processEncryptedMessage(clientId, message);
      }
    });

    connection.addEventListener('close', async (event) => {
      clearTimeout(authTimeout); // 清除超时计时器
      logEvent('close', [clientId, event.code, event.reason], 'debug');
      
      this.authenticatedClients.delete(clientId);
      this.authNonces.delete(clientId);

      const channel = this.clients[clientId].channel;

      if (channel && this.channels[channel]) {
        this.channels[channel].splice(this.channels[channel].indexOf(clientId), 1);

        if (this.channels[channel].length === 0) {
          delete(this.channels[channel]);
        } else {
          try {
            this.broadcastMemberList(channel);
          } catch (error) {
            logEvent('close-list', [clientId, error], 'error');
          }
        }
      }

      this.cleanupClient(clientId);
    });
  }

  // 处理验证消息
  handleAuthMessage(clientId, message, connection) {
    try {
      const authData = JSON.parse(message);
      
      // 验证消息格式
      if (!authData || authData.type !== 'auth' || !authData.username || !authData.passwordHash || !authData.nonce) {
        throw new Error('Invalid auth message format');
      }
      
      // 验证nonce防止重放攻击
      const storedNonce = this.authNonces.get(clientId);
      if (authData.nonce !== storedNonce) {
        throw new Error('Invalid nonce');
      }
      
      // 验证用户名和密码
      const storedHash = this.credentials.get(authData.username);
      if (!storedHash || !verifyPassword(authData.passwordHash, storedHash, storedNonce)) {
        this.sendMessage(connection, JSON.stringify({
          type: 'auth-failed',
          message: '用户名或密码错误'
        }));
        return;
      }
      
      // 验证通过
      this.authenticatedClients.add(clientId);
      this.clients[clientId].username = authData.username; // 存储用户名
      this.authNonces.delete(clientId); // 清除已使用的nonce
      
      this.sendMessage(connection, JSON.stringify({
        type: 'auth-success',
        message: '验证通过，正在建立连接...'
      }));
      
      // 发送服务器公钥
      this.sendMessage(connection, JSON.stringify({
        type: 'server-key',
        key: this.keyPair.rsaPublic
      }));
      
    } catch (error) {
      logEvent('auth-error', [clientId, error.message], 'error');
      this.sendMessage(connection, JSON.stringify({
        type: 'auth-error',
        message: '验证失败: ' + error.message
      }));
    }
  }

  processEncryptedMessage(clientId, message) {
    if (!this.authenticatedClients.has(clientId)) {
      logEvent('unauth-access', clientId, 'warning');
      this.closeConnection(this.clients[clientId].connection, 4401, 'Unauthorized');
      return;
    }

    let decrypted = null;

    try {
      decrypted = decryptMessage(message, this.clients[clientId].shared);

      // 增强：验证解密后的数据结构
      if (!isObject(decrypted) || !isString(decrypted.a) || !decrypted.timestamp) {
        throw new Error('Invalid message structure');
      }
      
      // 增强：检查消息时间戳，防止重放攻击（允许5分钟内的消息）
      const now = Date.now();
      if (Math.abs(decrypted.timestamp - now) > 5 * 60 * 1000) {
        throw new Error('Message timestamp out of range');
      }

      logEvent('message-decrypted', [clientId, decrypted.a], 'debug');

      const action = decrypted.a;

      if (action === 'j') {
        // 增强：验证频道名称合法性
        if (!/^[a-zA-Z0-9_-]{3,20}$/.test(decrypted.p)) {
          throw new Error('Invalid channel name');
        }
        this.handleJoinChannel(clientId, decrypted);
      } else if (action === 'c') {
        this.handleClientMessage(clientId, decrypted);
      } else if (action === 'w') {
        this.handleChannelMessage(clientId, decrypted);
      } else {
        throw new Error('Unknown action');
      }

    } catch (error) {
      logEvent('process-encrypted-message', [clientId, error.message], 'error');
      this.sendMessage(this.clients[clientId].connection, encryptMessage({
        type: 'error',
        message: 'Invalid message: ' + error.message
      }, this.clients[clientId].shared));
    } finally {
      decrypted = null;
    }
  }

  handleJoinChannel(clientId, decrypted) {
    if (!isString(decrypted.p) || this.clients[clientId].channel) {
      return;
    }

    try {
      const channel = decrypted.p;

      this.clients[clientId].channel = channel;

      if (!this.channels[channel]) {
        this.channels[channel] = [clientId];
      } else {
        // 增强：防止重复加入
        if (!this.channels[channel].includes(clientId)) {
          this.channels[channel].push(clientId);
        }
      }

      this.broadcastMemberList(channel);

    } catch (error) {
      logEvent('message-join', [clientId, error], 'error');
    }
  }

  handleClientMessage(clientId, decrypted) {
    if (!isString(decrypted.p) || !isString(decrypted.c) || !this.clients[clientId].channel) {
      return;
    }

    try {
      const channel = this.clients[clientId].channel;
      const targetClient = this.clients[decrypted.c];

      if (this.isClientInChannel(targetClient, channel)) {
        // 增强：添加发送者用户名
        const messageObj = {
          a: 'c',
          p: decrypted.p,
          c: clientId,
          u: this.clients[clientId].username,
          timestamp: Date.now()
        };

        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);
      }

    } catch (error) {
      logEvent('message-client', [clientId, error], 'error');
    }
  }

  handleChannelMessage(clientId, decrypted) {
    if (!isObject(decrypted.p) || !this.clients[clientId].channel) {
      return;
    }
    
    try {
      const channel = this.clients[clientId].channel;
      const validMembers = Object.keys(decrypted.p).filter(member => {
        const targetClient = this.clients[member];
        return isString(decrypted.p[member]) && this.isClientInChannel(targetClient, channel);
      });

      for (const member of validMembers) {
        const targetClient = this.clients[member];
        const messageObj = {
          a: 'c',
          p: decrypted.p[member],
          c: clientId,
          u: this.clients[clientId].username,
          timestamp: Date.now()
        };
        const encrypted = encryptMessage(messageObj, targetClient.shared);
        this.sendMessage(targetClient.connection, encrypted);
      }

    } catch (error) {
      logEvent('message-channel', [clientId, error], 'error');
    }
  }

  broadcastMemberList(channel) {
    try {
      const members = this.channels[channel];
      // 增强：包含用户名信息
      const memberInfo = members.map(id => ({
        id: id,
        username: this.clients[id]?.username || 'unknown'
      }));

      for (const member of members) {
        const client = this.clients[member];

        if (this.isClientInChannel(client, channel)) {
          const messageObj = {
            a: 'l',
            p: memberInfo.filter(info => info.id !== member)
          };

          const encrypted = encryptMessage(messageObj, client.shared);
          this.sendMessage(client.connection, encrypted);
        }
      }
    } catch (error) {
      logEvent('broadcast-member-list', error, 'error');
    }
  }

  isClientInChannel(client, channel) {
    return (
      client &&
      client.connection &&
      client.shared &&
      client.channel &&
      client.channel === channel &&
      this.authenticatedClients.has(clientId) // 增强：检查验证状态
    );
  }

  sendMessage(connection, message) {
    try {
      if (connection.readyState === 1) {
        connection.send(message);
      }
    } catch (error) {
      logEvent('sendMessage', error, 'error');
    }
  }

  closeConnection(connection, code, reason) {
    try {
      connection.close(code || 1000, reason || 'Normal closure');
    } catch (error) {
      logEvent('closeConnection', error, 'error');
    }
  }
  
  // 清理客户端数据
  cleanupClient(clientId) {
    if (this.clients[clientId]) {
      try {
        this.clients[clientId].connection.close();
      } catch (e) { /* 忽略关闭错误 */ }
      delete this.clients[clientId];
    }
  }
  
  async cleanupOldConnections() {
    const now = getTime();
    const seenThreshold = now - this.config.seenTimeout;
    const authThreshold = now - this.config.authTimeout;
    const clientsToRemove = [];

    for (const clientId in this.clients) {
      const client = this.clients[clientId];
      // 移除超时未活动或未完成验证的客户端
      if (client.seen < seenThreshold || 
          (!this.authenticatedClients.has(clientId) && client.authExpires < now)) {
        clientsToRemove.push(clientId);
      }
    }

    for (const clientId of clientsToRemove) {
      try {
        logEvent('connection-cleanup', clientId, 'debug');
        this.authenticatedClients.delete(clientId);
        this.authNonces.delete(clientId);
        this.cleanupClient(clientId);
      } catch (error) {
        logEvent('connection-cleanup', error, 'error');
      }
    }
    
    if (Object.keys(this.clients).length === 0 && Object.keys(this.channels).length === 0) {
      const pendingRotation = await this.state.storage.get('pendingKeyRotation');
      if (pendingRotation) {
        console.log('没有活跃客户端或房间，执行密钥轮换...');
        await this.state.storage.delete('rsaKeyPair');
        await this.state.storage.delete('pendingKeyRotation');
        this.keyPair = null;
        await this.initRSAKeyPair();
      }
    }
    
    return clientsToRemove.length;
  }
}
