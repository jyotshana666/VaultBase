'use strict';

require('dotenv').config();
const Redis = require('ioredis');

let redisClient = null;

function getRedisClient() {
  if (redisClient) return redisClient;

  const isTest = process.env.NODE_ENV === 'test';

  if (isTest && !process.env.REDIS_URL && !process.env.USE_REAL_REDIS) {
    const RedisMock = require('ioredis-mock');
    redisClient = new RedisMock();
    console.log('[Redis] Initialized in-memory test Redis mock (NODE_ENV=test)');
    return redisClient;
  }

  // Development & Production: MUST use real Redis instance
  const redisUrl = process.env.REDIS_URL;
  const redisOptions = {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || undefined,
    lazyConnect: false,
    maxRetriesPerRequest: 3,
    enableOfflineQueue: false,
  };

  redisClient = redisUrl ? new Redis(redisUrl, redisOptions) : new Redis(redisOptions);

  redisClient.on('error', (err) => {
    console.error('[Redis Error] Redis connection failure:', err.message);
  });

  redisClient.on('connect', () => {
    console.log('[Redis] Connected to Redis server successfully');
  });

  return redisClient;
}

async function checkHealth() {
  try {
    const client = getRedisClient();
    const pong = await client.ping();
    return pong === 'PONG';
  } catch (err) {
    return false;
  }
}

async function closeRedis() {
  if (redisClient) {
    await redisClient.quit();
    redisClient = null;
  }
}

module.exports = {
  getRedisClient,
  checkHealth,
  closeRedis,
};
