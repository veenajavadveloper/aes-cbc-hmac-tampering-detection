import * as crypto from "crypto";

const AES_ALGO = "aes-256-cbc";
const HMAC_ALGO = "sha256";

const ENC_KEY_LEN = 32;   // 256-bit AES
const MAC_KEY_LEN = 32;   // 256-bit HMAC
const IV_LEN = 16;
const HMAC_LEN = 32;

/**
 * Generate 64-byte master key (returned as HEX)
 */
export function generateMasterKeyHex(): string {
    return crypto.randomBytes(ENC_KEY_LEN + MAC_KEY_LEN).toString("hex");
}

function splitKeys(masterKeyHex: string) {
    const masterKey = Buffer.from(masterKeyHex, "hex");

    if (masterKey.length !== 64) {
        throw new Error("Master key must be 64 bytes (128 hex chars)");
    }

    return {
        encKey: masterKey.subarray(0, ENC_KEY_LEN),
        macKey: masterKey.subarray(ENC_KEY_LEN)
    };
}

/**
 * Encrypt (returns HEX string)
 */
export function encryptHex(
    plaintext: string,
    masterKeyHex: string
): string {

    const { encKey, macKey } = splitKeys(masterKeyHex);

    const iv = crypto.randomBytes(IV_LEN);

    const cipher = crypto.createCipheriv(AES_ALGO, encKey, iv);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final()
    ]);

    // HMAC over (IV + ciphertext)
    const hmac = crypto.createHmac(HMAC_ALGO, macKey)
        .update(iv)
        .update(ciphertext)
        .digest();

    const payload = Buffer.concat([iv, ciphertext, hmac]);

    return payload.toString("hex");
}

/**
 * Decrypt (input must be HEX string)
 */
export function decryptHex(
    payloadHex: string,
    masterKeyHex: string
): string {

    const { encKey, macKey } = splitKeys(masterKeyHex);

    const payload = Buffer.from(payloadHex, "hex");

    if (payload.length < IV_LEN + HMAC_LEN) {
        throw new Error("Invalid payload");
    }

    const iv = payload.subarray(0, IV_LEN);
    const hmacStart = payload.length - HMAC_LEN;

    const ciphertext = payload.subarray(IV_LEN, hmacStart);
    const receivedHmac = payload.subarray(hmacStart);

    // Recompute HMAC
    const expectedHmac = crypto.createHmac(HMAC_ALGO, macKey)
        .update(iv)
        .update(ciphertext)
        .digest();

    if (!crypto.timingSafeEqual(receivedHmac, expectedHmac)) {
        throw new Error("Authentication failed: Data tampered");
    }

    const decipher = crypto.createDecipheriv(AES_ALGO, encKey, iv);

    const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);

    return decrypted.toString("utf8");
}