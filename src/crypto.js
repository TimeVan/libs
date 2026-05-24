'use strict';

const nodeCrypto = require('crypto');
const assert = require('assert');

function assertBuffer(value) {
    if (!(value instanceof Buffer)) {
        throw TypeError(`Expected Buffer instead of: ${value.constructor.name}`);
    }
    return value;
}

function generateSalt(length = 32) {
    return nodeCrypto.randomBytes(length);
}

function generateNonce(length = 12) {
    return nodeCrypto.randomBytes(length);
}

function deriveKeyPBKDF2(password, salt, iterations = 210000, keylen = 32) {
    assertBuffer(password);
    assertBuffer(salt);
    return nodeCrypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha512');
}

function deriveKeyScrypt(password, salt, N = 16384, r = 8, p = 1, keylen = 32) {
    assertBuffer(password);
    assertBuffer(salt);
    return nodeCrypto.scryptSync(password, salt, keylen, { N, r, p });
}

function deriveSecrets(input, salt, info, chunks) {
    assertBuffer(input);
    assertBuffer(salt);
    assertBuffer(info);
    if (salt.byteLength != 32) {
        throw new Error("Got salt of incorrect length");
    }
    chunks = chunks || 3;
    assert(chunks >= 1 && chunks <= 3);
    
    const PRK = calculateMAC(salt, input);
    const infoArray = new Uint8Array(info.byteLength + 1 + 64);
    infoArray.set(info, 64);
    infoArray[infoArray.length - 1] = 1;
    const signed = [calculateMAC(PRK, Buffer.from(infoArray.slice(64)))];
    
    if (chunks > 1) {
        infoArray.set(signed[signed.length - 1].slice(0, 64));
        infoArray[infoArray.length - 1] = 2;
        signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
    }
    if (chunks > 2) {
        infoArray.set(signed[signed.length - 1].slice(0, 64));
        infoArray[infoArray.length - 1] = 3;
        signed.push(calculateMAC(PRK, Buffer.from(infoArray)));
    }
    return signed.map(s => s.slice(0, 32));
}

function encryptAES256GCM(key, data, additionalData = null) {
    assertBuffer(key);
    assertBuffer(data);
    
    if (key.length !== 32) {
        throw new Error("AES-256 requires 32-byte key");
    }
    
    const iv = generateNonce(12);
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
    
    if (additionalData) {
        cipher.setAAD(additionalData);
    }
    
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return Buffer.concat([iv, authTag, encrypted]);
}

function decryptAES256GCM(key, encryptedData, additionalData = null) {
    assertBuffer(key);
    assertBuffer(encryptedData);
    
    if (key.length !== 32) {
        throw new Error("AES-256 requires 32-byte key");
    }
    
    if (encryptedData.length < 28) {
        throw new Error("Invalid encrypted data length");
    }
    
    const iv = encryptedData.slice(0, 12);
    const authTag = encryptedData.slice(12, 28);
    const encrypted = encryptedData.slice(28);
    
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    if (additionalData) {
        decipher.setAAD(additionalData);
    }
    
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
function encryptChaCha20(key, data, additionalData = null) {
    assertBuffer(key);
    assertBuffer(data);
    
    if (key.length !== 32) {
        throw new Error("ChaCha20 requires 32-byte key");
    }
    
    const nonce = generateNonce(12); // 96-bit nonce
    const cipher = nodeCrypto.createCipheriv('chacha20-poly1305', key, nonce, {
        authTagLength: 16
    });
    
    if (additionalData) {
        cipher.setAAD(additionalData);
    }
    
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return Buffer.concat([nonce, authTag, encrypted]);
}

function decryptChaCha20(key, encryptedData, additionalData = null) {
    assertBuffer(key);
    assertBuffer(encryptedData);
    
    if (key.length !== 32) {
        throw new Error("ChaCha20 requires 32-byte key");
    }
    
    if (encryptedData.length < 28) {
        throw new Error("Invalid encrypted data length");
    }
    
    const nonce = encryptedData.slice(0, 12);
    const authTag = encryptedData.slice(12, 28);
    const encrypted = encryptedData.slice(28);
    
    const decipher = nodeCrypto.createDecipheriv('chacha20-poly1305', key, nonce, {
        authTagLength: 16
    });
    decipher.setAuthTag(authTag);
    
    if (additionalData) {
        decipher.setAAD(additionalData);
    }
    
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}
function encryptAES256CBC(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
}

function decryptAES256CBC(key, data, iv) {
    assertBuffer(key);
    assertBuffer(data);
    assertBuffer(iv);
    const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
}
function encryptMultiLayer(masterKey, data, additionalData = null) {
    assertBuffer(masterKey);
    assertBuffer(data);
    
    if (masterKey.length !== 64) {
        throw new Error("Multi-layer encryption requires 64-byte master key");
    }
    
    const salt = generateSalt(32);
    const derivedKeys = deriveSecrets(masterKey, salt, Buffer.from('MULTILAYER'), 2);
    const key1 = derivedKeys[0];
    const key2 = derivedKeys[1];
    
    const layer1 = encryptAES256GCM(key1, data, additionalData);
    
    const layer2 = encryptChaCha20(key2, layer1, additionalData);
    
    return Buffer.concat([salt, layer2]);
}

function decryptMultiLayer(masterKey, encryptedData, additionalData = null) {
    assertBuffer(masterKey);
    assertBuffer(encryptedData);
    
    if (masterKey.length !== 64) {
        throw new Error("Multi-layer encryption requires 64-byte master key");
    }
    
    if (encryptedData.length < 32) {
        throw new Error("Invalid encrypted data length");
    }
    
    const salt = encryptedData.slice(0, 32);
    const layer2 = encryptedData.slice(32);
    
    const derivedKeys = deriveSecrets(masterKey, salt, Buffer.from('MULTILAYER'), 2);
    const key1 = derivedKeys[0];
    const key2 = derivedKeys[1];
    
    const layer1 = decryptChaCha20(key2, layer2, additionalData);
    
    const data = decryptAES256GCM(key1, layer1, additionalData);
    
    return data;
}
function encryptTripleLayer(masterKey, data, additionalData = null) {
    assertBuffer(masterKey);
    assertBuffer(data);
    
    if (masterKey.length !== 64) {
        throw new Error("Triple-layer encryption requires 64-byte master key");
    }
    
    const salt = generateSalt(32);
    const derivedKeys = deriveSecrets(masterKey, salt, Buffer.from('TRIPLELAYER'), 3);
    const key1 = derivedKeys[0];
    const key2 = derivedKeys[1];
    const key3 = derivedKeys[2];
    
    const layer1 = encryptAES256GCM(key1, data, additionalData);
    
    const layer2 = encryptChaCha20(key2, layer1, additionalData);
    
    const layer3 = encryptAES256GCM(key3, layer2, additionalData);
    
    return Buffer.concat([salt, layer3]);
}

function decryptTripleLayer(masterKey, encryptedData, additionalData = null) {
    assertBuffer(masterKey);
    assertBuffer(encryptedData);
    
    if (masterKey.length !== 64) {
        throw new Error("Triple-layer encryption requires 64-byte master key");
    }
    
    if (encryptedData.length < 32) {
        throw new Error("Invalid encrypted data length");
    }
    
    const salt = encryptedData.slice(0, 32);
    const layer3 = encryptedData.slice(32);
    
    const derivedKeys = deriveSecrets(masterKey, salt, Buffer.from('TRIPLELAYER'), 3);
    const key1 = derivedKeys[0];
    const key2 = derivedKeys[1];
    const key3 = derivedKeys[2];
    
    const layer2 = decryptAES256GCM(key3, layer3, additionalData);
    
    const layer1 = decryptChaCha20(key2, layer2, additionalData);
    
    const data = decryptAES256GCM(key1, layer1, additionalData);
    
    return data;
}
function calculateMAC(key, data) {
    assertBuffer(key);
    assertBuffer(data);
    const hmac = nodeCrypto.createHmac('sha512', key);
    hmac.update(data);
    return Buffer.from(hmac.digest());
}

function verifyMAC(data, key, mac, length) {
    const calculatedMac = calculateMAC(key, data).slice(0, length);
    if (mac.length !== length || calculatedMac.length !== length) {
        throw new Error("Bad MAC length");
    }
    if (!nodeCrypto.timingSafeEqual(mac, calculatedMac)) {
        throw new Error("Bad MAC");
    }
}
function hash(data, algorithm = 'sha512') {
    assertBuffer(data);
    const hasher = nodeCrypto.createHash(algorithm);
    hasher.update(data);
    return hasher.digest();
}

function hashSHA256(data) {
    return hash(data, 'sha256');
}

function hashSHA512(data) {
    return hash(data, 'sha512');
}

function hashSHA3_512(data) {
    return hash(data, 'sha3-512');
}
function encrypt(key, data, iv = null) {
    if (iv) {
        return encryptAES256CBC(key, data, iv);
    } else {
        return encryptAES256GCM(key, data);
    }
}

function decrypt(key, data, iv = null) {
    if (iv) {
        return decryptAES256CBC(key, data, iv);
    } else {
        return decryptAES256GCM(key, data);
    }
}
module.exports = {
    deriveSecrets,
    deriveKeyPBKDF2,
    deriveKeyScrypt,
    
    encrypt,
    decrypt,
    encryptAES256GCM,
    decryptAES256GCM,
    encryptAES256CBC,
    decryptAES256CBC,
    encryptChaCha20,
    decryptChaCha20,
    
    encryptMultiLayer,
    decryptMultiLayer,
    encryptTripleLayer,
    decryptTripleLayer,
    
    hash,
    hashSHA256,
    hashSHA512,
    hashSHA3_512,
    
    calculateMAC,
    verifyMAC,
    
    generateSalt,
    generateNonce
};
