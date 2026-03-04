import {
    generateMasterKeyHex,
    encryptHex,
    decryptHex
} from "../src/index.ts";

    console.log("AES-256-CBC + HMAC (HEX)");

    const masterKeyHex = generateMasterKeyHex();

    console.log("Master Key (hex):", masterKeyHex);

    const message = "Secure message to encrypt";

    console.log("Plaintext:", message);

    const encryptedHex = encryptHex(message, masterKeyHex);

    console.log("Encrypted Payload (hex):", encryptedHex);// iv ciphertext hmac

    // bb12d8024c5f57b17d5965197bfc2b77 d2ffdb4672d8a9a017312c4c838747e32a129979e5f57bebe982ea0a75b743dd ea8f6e49d76bb182953eb4d88bf12d6d52f34ddd481a936a72fca90ae55d1ce7

    const decrypted = decryptHex(encryptedHex, masterKeyHex);

    console.log("Decrypted:", decrypted);

    if (decrypted !== message) {
        throw new Error("Decryption failed");
    }

    console.log("✔ Encryption/Decryption successful");

    // Tampering test
    console.log("Testing tampering detection...");

    // negative test: modified the encrypted hex to (simulate tampering)
    const tamperedHex =
        encryptedHex.substring(0, encryptedHex.length - 4) + "abcd";

    try {
        decryptHex(tamperedHex, masterKeyHex);
        console.error("❌ Tampering NOT detected");
    } catch {
        console.log("✔ Tampering detected successfully");
    }



