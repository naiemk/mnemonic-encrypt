const crypto = require("crypto");
const bip39 = require('bip39');
const ethWallet = require('ethereumjs-wallet');
const Wallet = ethWallet.default;
const bitcoin = require('bitcoinjs-lib');
const hdkey = require('hdkey');

const pwHashLoop = 100000;

function hash(pw) {
    let h = crypto.createHash('sha256');
    h.update('PRE_' + pw + '_POST');
    return h.digest('hex');
}

function toPw(pw) {
    let h = crypto.createHash('sha256');
    h.update('PRE_' + pw + '_POST');
    for(let i=0; i<pwHashLoop; i++) {
        h.update('PRE_' + i.toString() + pw + i.toString() + '_POST')
    }
    return h.digest('hex');
}

function crypt(pw, mn, isEncrypt, ignoreMnChecksum) {
    const pp = toPw(pw);
    console.log('Password after digest: ', pp);
    const msg = bip39.mnemonicToEntropy(mn);
    const b1 = Buffer.from(pp, 'hex');
    const b2 = Buffer.from(msg, 'hex');
    if (b1.length != 32 || b2.length != 32) {
      if (!ignoreMnChecksum) {
        throw new Error('Both pw and mn must be 32 bytes');
      }
    }
    var res = []
    for (var i = 0; i < b1.length; i++) {
       res.push(b1[i] ^ b2[i])
    }
    const rv = bip39.entropyToMnemonic(Buffer.from(res));
    if (!bip39.validateMnemonic(rv)) {
        throw new Error('Invalid mnemonic was entered!');
    }
    return [rv, hash(isEncrypt ? mn : rv).substr(0,8), mnemonicAddrs(isEncrypt ? mn : rv)];
}

function toPwTest(pw) {
    return toPw('Some prefix ' + pw + ' Some post fix');
}

function verifyPw(pw, res) {
    const pp = toPwTest(pw);
    return pp.substring(0, 8) === res.substring(0, 8);
}

function newMnemonic() {
    const sk = crypto.randomBytes(32).toString('hex');
    return bip39.entropyToMnemonic(sk);
}

function mnemonicAddrsEthBtc(mnemonic, der=undefined) {
  const addrEth = entropyToEthAddr(mnemonic, der)[0];
  const addrBtc = entropyToBtcAddr(mnemonic, der)[0];
  return [addrEth, addrBtc];
}

function mnemonicKeysEthBtc(mnemonic, der=undefined) {
  const keyEth = entropyToEthAddr(mnemonic, der)[1];
  const keyBtc = entropyToBtcAddr(mnemonic, der)[1];
  return [keyEth, keyBtc];
}

function mnemonicAddrs(mnemonic, der) {
  const [addrEth, addrBtc] = mnemonicAddrsEthBtc(mnemonic, der);
  return `ETH: "${addrEth}" - BTC: "${addrBtc}"`;
}

function entropyToEthAddr(mnemonic, der=0) {
  // Generate seed from mnemonic
  const seed = bip39.mnemonicToSeedSync(mnemonic);

  // Derive Ethereum key using BIP44
  const hdWallet = hdkey.fromMasterSeed(seed);
  const path = `m/44'/60'/0'/0/${der}`; // Ethereum derivation path
  const childKey = hdWallet.derive(path);
  const ethWallet = Wallet.fromPrivateKey(childKey.privateKey);
  const ethAddress = ethWallet.getAddressString();

  return [ethAddress, childKey];
}

function entropyToBtcAddr(mnemonic, der=0) {
  // Generate seed from mnemonic
  const seed = bip39.mnemonicToSeedSync(mnemonic);

  // Derive Bitcoin key using BIP44
  const hdWallet = hdkey.fromMasterSeed(seed);
  const path = `m/44'/0'/0'/0/${der}`; // Bitcoin derivation path
  const childKey = hdWallet.derive(path);
  const { address } = bitcoin.payments.p2pkh({ pubkey: childKey.publicKey });

  return [address, childKey];
}


module.exports = {
    verifyPw, crypt, toPwTest, newMnemonic, mnemonicAddrs, mnemonicAddrsEthBtc, mnemonicKeysEthBtc,
}
