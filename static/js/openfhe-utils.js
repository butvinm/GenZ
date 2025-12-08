Uint8Array.prototype.toBase64 = function() {
    let binary = '';
    const len = this.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(this[i]);
    }
    return btoa(binary);
};

Uint8Array.fromBase64 = function(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
};

export async function initOpenFHE() {
    const factory = await import('/static/js/openfhe/openfhe_pke_es6.js');
    const openfhe = await factory.default();
    return openfhe;
}

export function generateBGVContext(openfhe) {
    const params = new openfhe.CCParamsCryptoContextBGVRNS();
    params.SetMultiplicativeDepth(2);
    params.SetPlaintextModulus(65537);
    params.SetSecurityLevel(openfhe.SecurityLevel.HEStd_128_classic);

    const cc = new openfhe.GenCryptoContextBGV(params);
    cc.Enable(openfhe.PKESchemeFeature.PKE);
    cc.Enable(openfhe.PKESchemeFeature.LEVELEDSHE);

    const keyPair = cc.KeyGen();

    return { cc, keyPair };
}

export function serializePublicKey(openfhe, publicKey) {
    const serialized = openfhe.SerializePublicKeyToBuffer(
        publicKey,
        openfhe.SerType.BINARY
    );
    return serialized.toBase64();
}

export async function registerPublicKey(publicKeyBase64) {
    const response = await fetch('/api/v0.1.0/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ publicKey: publicKeyBase64 })
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Registration failed (${response.status}): ${text}`);
    }

    return await response.json();
}
