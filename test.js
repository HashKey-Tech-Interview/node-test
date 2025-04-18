const express = require('express');
const BigNumber = require('bignumber.js');
const multihash = require('multihash');
const EventEmitter = require('eventemitter3');
const { SignJWT, jwtVerify } = require('jose');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
const nodelogex = require('nodelogex');
const { ethers } = require('ethers');
const Queue = require('bull');
const Redis = require('redis');
const _ = require('lodash');
const moment = require('moment');
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const port = 3000;

app.use(express.json());

const logger = nodelogex.createLogger({
  level: 'info',
  format: nodelogex.format.combine(
    nodelogex.format.timestamp(),
    nodelogex.format.json()
  ),
  transports: [
    new nodelogex.transports.File({ filename: 'transactions.log' }),
    new nodelogex.transports.Console()
  ]
});

const redisClient = Redis.createClient({ url: 'redis://localhost:6379' });
redisClient.connect().catch(err => logger.error({ event: 'redis_connect_error', error: err.message }));

// Use environment variables for sensitive information
const provider = new ethers.providers.JsonRpcProvider(`https://sepolia.infura.io/v3/${process.env.INFURA_PROJECT_ID}`);
const signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const txQueue = new Queue('transaction-processing', 'redis://localhost:6379');
const rewardQueue = new Queue('reward-distribution', 'redis://localhost:6379');
const events = new EventEmitter();

const tokenAddress = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'; 
const tokenABI = [
  {"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"success","type":"bool"}],"type":"function"},
  {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}
];
const contract = new ethers.Contract(tokenAddress, tokenABI, signer);

mongoose.connect('mongodb://localhost:27017/defi', { useNewUrlParser: true, useUnifiedTopology: true });
const UserSchema = new mongoose.Schema({
  wallet: String,
  portfolio: { type: Map, of: String },
  stakes: { type: Map, of: Object }, // Changed to store objects with amount and timestamp
  nonce: { type: Number, default: 0 },
  lastActivity: String
});
const User = mongoose.model('User', UserSchema);

const JWT_SECRET = new TextEncoder().encode('your-secret-key');
const STAKING_REWARD_RATE = new BigNumber('0.05'); // 5% APR
let liquidityPools = { 'USDC-ETH': { total: new BigNumber('0'), users: {} } };

async function getTokenBalance(wallet) {
  try {
    const balance = await contract.balanceOf(wallet);
    return new BigNumber(ethers.utils.formatUnits(balance, 6)); // USDC has 6 decimals
  } catch (error) {
    logger.error({ event: 'get_balance_error', wallet, error: error.message });
    return new BigNumber('0');
  }
}

async function generateTxHash(data) {
  const buffer = Buffer.from(JSON.stringify(data));
  return multihash.encode(buffer, 'sha2-256').toString('hex'); 
}

app.post('/register', async (req, res) => {
  try {
    const { wallet } = req.body;
    if (!ethers.utils.isAddress(wallet)) return res.status(400).send('Invalid wallet');

    const existingUser = await User.findOne({ wallet });
    if (existingUser) return res.status(409).send('User already registered');

    const balance = await getTokenBalance(wallet);
    const user = new User({
      wallet,
      portfolio: new Map([['USDC', balance.toString()]]),
      stakes: new Map(),
      lastActivity: moment().toISOString()
    });
    await user.save();

    const token = await new SignJWT({ wallet })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('1h')
      .sign(JWT_SECRET);
    
    logger.info({ event: 'user_registered', wallet });
    res.status(201).json({ wallet, token });
  } catch (error) {
    logger.error({ event: 'register_error', error: error.message });
    res.status(500).send('Registration failed');
  }
});

app.post('/transfer', async (req, res) => {
  try {
    const { from, to, amount } = req.body;
    
    if (!from || !to || !amount) {
      return res.status(400).send('Missing required parameters');
    }
    
    // Validate addresses
    if (!ethers.utils.isAddress(from) || !ethers.utils.isAddress(to)) {
      return res.status(400).send('Invalid wallet address');
    }
    
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send('No token provided');
    
    const token = authHeader.split(' ')[1];
    const { payload } = await jwtVerify(token, JWT_SECRET);
    if (payload.wallet !== from) return res.status(403).send('Unauthorized');

    const user = await User.findOne({ wallet: from });
    if (!user) return res.status(404).send('User not found');

    // FIX 1: Parse amount as BigNumber for precision
    const bnAmount = new BigNumber(amount);
    
    // Validate amount
    if (bnAmount.isNaN() || bnAmount.lte(0)) {
      return res.status(400).send('Invalid amount');
    }
    
    // Check user balance
    const userBalance = new BigNumber(user.portfolio.get('USDC') || '0');
    if (userBalance.lt(bnAmount)) {
      return res.status(400).send('Insufficient balance');
    }

    // FIX 2: Parse the amount with proper decimals for blockchain transaction
    const parsedAmount = ethers.utils.parseUnits(bnAmount.toString(), 6); // USDC has 6 decimals
    
    // Execute blockchain transaction
    const tx = await contract.transfer(to, parsedAmount);
    const receipt = await tx.wait();
    
    // Queue the transaction processing with stringified amount
    txQueue.add({
      from,
      to,
      amount: bnAmount.toString(),
      txHash: receipt.transactionHash,
      nonce: user.nonce
    });
    
    user.nonce += 1;
    events.emit('tx', { txHash: receipt.transactionHash, status: 'pending' });
    
    res.json({ txHash: receipt.transactionHash });
  } catch (error) {
    logger.error({ event: 'transfer_error', error: error.message });
    res.status(500).send('Transfer failed');
  }
});

app.post('/stake', async (req, res) => {
  try {
    const { wallet, amount, pool } = req.body;
    
    if (!wallet || !amount || !pool) {
      return res.status(400).send('Missing required parameters');
    }
    
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send('No token provided');
    
    const token = authHeader.split(' ')[1];
    const { payload } = await jwtVerify(token, JWT_SECRET);
    if (payload.wallet !== wallet) return res.status(403).send('Unauthorized');

    const user = await User.findOne({ wallet });
    if (!user || !liquidityPools[pool]) return res.status(400).send('Invalid input');

    const bnAmount = new BigNumber(amount);
    if (bnAmount.isNaN() || bnAmount.lte(0)) {
      return res.status(400).send('Invalid amount');
    }
    
    const userBalance = new BigNumber(user.portfolio.get('USDC') || '0');
    if (userBalance.lt(bnAmount)) return res.status(400).send('Insufficient balance');

    // FIX 3: Store stake with timestamp for accurate reward calculation
    const stakeInfo = {
      amount: bnAmount.toString(),
      timestamp: Date.now(),
      lastRewardTime: Date.now()
    };
    
    // Update user's stakes with the new stake info
    const existingStake = user.stakes.get(pool);
    if (existingStake) {
      stakeInfo.amount = new BigNumber(existingStake.amount).plus(bnAmount).toString();
      // Keep the earliest timestamp for APR calculation
      stakeInfo.timestamp = Math.min(existingStake.timestamp, Date.now());
      stakeInfo.lastRewardTime = Date.now();
    }
    
    user.stakes.set(pool, stakeInfo);
    user.portfolio.set('USDC', userBalance.minus(bnAmount).toString());
    
    // Update pool info
    liquidityPools[pool].total = liquidityPools[pool].total.plus(bnAmount);
    liquidityPools[pool].users[wallet] = (new BigNumber(
      liquidityPools[pool].users[wallet] || '0'
    )).plus(bnAmount).toString();
    
    user.lastActivity = moment().toISOString();
    await user.save();

    const stakeHash = await generateTxHash({ wallet, amount: bnAmount.toString(), pool });
    logger.info({ event: 'stake_executed', wallet, amount: bnAmount.toString(), pool, stakeHash });
    
    res.json({ stakeHash, amount: bnAmount.toString() });
  } catch (error) {
    logger.error({ event: 'stake_error', error: error.message });
    res.status(500).send('Staking failed');
  }
});

app.post('/unstake', async (req, res) => {
  try {
    const { wallet, amount, pool } = req.body;
    
    if (!wallet || !amount || !pool) {
      return res.status(400).send('Missing required parameters');
    }
    
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send('No token provided');
    
    const token = authHeader.split(' ')[1];
    const { payload } = await jwtVerify(token, JWT_SECRET);
    if (payload.wallet !== wallet) return res.status(403).send('Unauthorized');

    const user = await User.findOne({ wallet });
    if (!user || !liquidityPools[pool]) return res.status(400).send('Invalid input');

    const bnAmount = new BigNumber(amount);
    if (bnAmount.isNaN() || bnAmount.lte(0)) {
      return res.status(400).send('Invalid amount');
    }
    
    const stakeInfo = user.stakes.get(pool);
    if (!stakeInfo) return res.status(400).send('No stake found');
    
    const stakedAmount = new BigNumber(stakeInfo.amount);
    if (stakedAmount.lt(bnAmount)) return res.status(400).send('Insufficient stake');

    // FIX 4: Calculate reward based on time elapsed and APR
    const stakingDuration = moment().diff(moment(stakeInfo.timestamp), 'days');
    const annualizedDuration = new BigNumber(stakingDuration).dividedBy(365); // Convert days to years
    const reward = bnAmount.times(STAKING_REWARD_RATE).times(annualizedDuration);
    
    logger.info({
      event: 'reward_calculation',
      wallet,
      stakingDuration,
      annualizedDuration: annualizedDuration.toString(),
      stakeAmount: bnAmount.toString(),
      rate: STAKING_REWARD_RATE.toString(),
      reward: reward.toString()
    });

    // Update user's stakes and portfolio
    const remainingStake = stakedAmount.minus(bnAmount);
    if (remainingStake.isZero()) {
      user.stakes.delete(pool);
    } else {
      user.stakes.set(pool, {
        amount: remainingStake.toString(),
        timestamp: stakeInfo.timestamp,
        lastRewardTime: Date.now()
      });
    }
    
    // Add unstaked amount plus reward to portfolio
    const currentBalance = new BigNumber(user.portfolio.get('USDC') || '0');
    user.portfolio.set('USDC', currentBalance.plus(bnAmount).plus(reward).toString());
    
    // Update pool info
    liquidityPools[pool].total = liquidityPools[pool].total.minus(bnAmount);
    liquidityPools[pool].users[wallet] = (new BigNumber(
      liquidityPools[pool].users[wallet] || '0'
    )).minus(bnAmount).toString();
    
    user.lastActivity = moment().toISOString();
    await user.save();

    logger.info({ 
      event: 'unstake_executed', 
      wallet, 
      amount: bnAmount.toString(), 
      reward: reward.toString(), 
      pool 
    });
    
    res.json({ 
      amount: bnAmount.toString(), 
      reward: reward.toString() 
    });
  } catch (error) {
    logger.error({ event: 'unstake_error', error: error.message });
    res.status(500).send('Unstaking failed');
  }
});

app.get('/portfolio/:wallet', async (req, res) => {
  try {
    const user = await User.findOne({ wallet: req.params.wallet });
    if (!user) return res.status(404).send('User not found');

    // Calculate pending rewards for each stake
    const stakes = {};
    let totalPendingRewards = new BigNumber(0);
    
    for (const [pool, stakeInfo] of user.stakes.entries()) {
      const stakedAmount = new BigNumber(stakeInfo.amount);
      const stakingDuration = moment().diff(moment(stakeInfo.timestamp), 'days');
      const annualizedDuration = new BigNumber(stakingDuration).dividedBy(365);
      const pendingReward = stakedAmount.times(STAKING_REWARD_RATE).times(annualizedDuration);
      
      stakes[pool] = {
        amount: stakedAmount.toString(),
        stakingSince: new Date(stakeInfo.timestamp).toISOString(),
        pendingReward: pendingReward.toString()
      };
      
      totalPendingRewards = totalPendingRewards.plus(pendingReward);
    }

    // Update portfolio with current blockchain balance
    const onChainBalance = await getTokenBalance(req.params.wallet);
    
    // Get price data for conversion to USD
    const prices = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd');
    const ethPrice = prices.data.ethereum.usd;
    
    res.json({
      wallet: req.params.wallet,
      portfolio: {
        USDC: user.portfolio.get('USDC') || '0',
        onChainBalance: onChainBalance.toString()
      },
      stakes,
      totalPendingRewards: totalPendingRewards.toString(),
      ethPrice
    });
  } catch (error) {
    logger.error({ event: 'portfolio_error', error: error.message });
    res.status(500).send('Failed to retrieve portfolio');
  }
});

// FIX 5: Properly update balances in transaction queue processing
txQueue.process(async (job) => {
  try {
    const { from, to, amount, txHash } = job.data;
    logger.info({ event: 'processing_transaction', txHash, from, to, amount });
    
    const bnAmount = new BigNumber(amount);
    
    // Update sender's balance
    const fromUser = await User.findOne({ wallet: from });
    if (fromUser) {
      const fromBalance = new BigNumber(fromUser.portfolio.get('USDC') || '0');
      
      // Ensure the sender has sufficient balance
      if (fromBalance.gte(bnAmount)) {
        fromUser.portfolio.set('USDC', fromBalance.minus(bnAmount).toString());
        fromUser.lastActivity = moment().toISOString();
        await fromUser.save();
        logger.info({ event: 'sender_updated', wallet: from, newBalance: fromBalance.minus(bnAmount).toString() });
      } else {
        logger.error({ event: 'insufficient_balance', wallet: from, balance: fromBalance.toString(), amount });
      }
    }
    
    // Update or create recipient's record
    let toUser = await User.findOne({ wallet: to });
    if (toUser) {
      const toBalance = new BigNumber(toUser.portfolio.get('USDC') || '0');
      toUser.portfolio.set('USDC', toBalance.plus(bnAmount).toString());
      toUser.lastActivity = moment().toISOString();
      await toUser.save();
      logger.info({ event: 'recipient_updated', wallet: to, newBalance: toBalance.plus(bnAmount).toString() });
    } else {
      // Create new user if not exists
      toUser = new User({
        wallet: to,
        portfolio: new Map([['USDC', bnAmount.toString()]]),
        stakes: new Map(),
        lastActivity: moment().toISOString()
      });
      await toUser.save();
      logger.info({ event: 'recipient_created', wallet: to, initialBalance: bnAmount.toString() });
    }
    
    events.emit('tx', { txHash, status: 'completed' });
  } catch (error) {
    logger.error({ event: 'tx_processing_error', error: error.message });
    events.emit('tx', { txHash: job.data.txHash, status: 'failed', error: error.message });
  }
});

// FIX 6: Add periodic reward distribution system
function setupRewardDistribution() {
  // Schedule reward distribution daily
  rewardQueue.add({}, {
    repeat: {
      cron: '0 0 * * *' // Run at midnight every day
    }
  });
  
  // Process scheduled reward distributions
  rewardQueue.process(async (job) => {
    logger.info({ event: 'reward_distribution_started' });
    
    // Find all users with active stakes
    const users = await User.find({ 'stakes.size': { $gt: 0 } });
    let totalRewardsDistributed = new BigNumber(0);
    
    for (const user of users) {
      let userRewards = new BigNumber(0);
      
      // Process each stake for the user
      for (const [pool, stakeInfo] of user.stakes.entries()) {
        if (!liquidityPools[pool]) continue;
        
        const stakedAmount = new BigNumber(stakeInfo.amount);
        if (stakedAmount.lte(0)) continue;
        
        // Calculate reward based on time since last reward distribution
        const timeSinceLastReward = moment().diff(moment(stakeInfo.lastRewardTime), 'days');
        if (timeSinceLastReward <= 0) continue;
        
        const annualizedDuration = new BigNumber(timeSinceLastReward).dividedBy(365);
        const reward = stakedAmount.times(STAKING_REWARD_RATE).times(annualizedDuration);
        
        if (reward.gt(0)) {
          userRewards = userRewards.plus(reward);
          
          // Update last reward time
          stakeInfo.lastRewardTime = Date.now();
          user.stakes.set(pool, stakeInfo);
          
          logger.info({
            event: 'stake_reward_calculated',
            wallet: user.wallet,
            pool,
            stakedAmount: stakedAmount.toString(),
            timeSinceLastReward,
            reward: reward.toString()
          });
        }
      }
      
      if (userRewards.gt(0)) {
        // Add rewards to user's portfolio
        const currentBalance = new BigNumber(user.portfolio.get('USDC') || '0');
        user.portfolio.set('USDC', currentBalance.plus(userRewards).toString());
        
        totalRewardsDistributed = totalRewardsDistributed.plus(userRewards);
        
        logger.info({
          event: 'user_rewards_distributed',
          wallet: user.wallet,
          rewards: userRewards.toString(),
          newBalance: currentBalance.plus(userRewards).toString()
        });
        
        // Save the updated user
        user.lastActivity = moment().toISOString();
        await user.save();
      }
    }
    
    // Emit event for the distribution
    events.emit('rewards_distributed', {
      timestamp: moment().toISOString(),
      totalRewards: totalRewardsDistributed.toString(),
      usersAffected: users.length
    });
    
    logger.info({
      event: 'reward_distribution_completed',
      totalRewards: totalRewardsDistributed.toString(),
      usersAffected: users.length
    });
  });
  
  return rewardQueue;
}

// Set up reward distribution
const rewardDistributor = setupRewardDistribution();

// Listen for reward distribution events
events.on('rewards_distributed', (data) => {
  io.emit('rewards_update', data);
});

// Listen for transaction events
events.on('tx', (data) => {
  io.emit('tx_status_update', data);
});

server.listen(port, () => logger.info(`Server running at http://localhost:${port}`));

// Export for testing
module.exports = {
  app,
  events,
  txQueue,
  rewardQueue
};