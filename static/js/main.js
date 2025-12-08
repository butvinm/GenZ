import { initOpenFHE, generateBGVContext, serializePublicKey, registerPublicKey } from './openfhe-utils.js';

const generateBtn = document.getElementById('generateBtn');
const loadingDiv = document.getElementById('loading');
const loadingText = document.getElementById('loadingText');
const resultDiv = document.getElementById('result');
const errorDiv = document.getElementById('error');
const errorMessage = document.getElementById('errorMessage');
const sessionIdSpan = document.getElementById('sessionId');

let openfhe = null;

function setLoading(isLoading, message = '') {
    generateBtn.disabled = isLoading;
    loadingDiv.classList.toggle('hidden', !isLoading);
    if (message) loadingText.textContent = message;
}

function showResult(sessionId) {
    resultDiv.classList.remove('hidden');
    errorDiv.classList.add('hidden');
    sessionIdSpan.textContent = sessionId;
}

function showError(error) {
    errorDiv.classList.remove('hidden');
    resultDiv.classList.add('hidden');
    errorMessage.textContent = error.message || error.toString();
    console.error('Registration error:', error);
}

async function handleGenerateKey() {
    try {
        resultDiv.classList.add('hidden');
        errorDiv.classList.add('hidden');

        if (!openfhe) {
            setLoading(true, 'Loading OpenFHE WASM module...');
            openfhe = await initOpenFHE();
            console.log('OpenFHE WASM module loaded');
        }

        setLoading(true, 'Generating BGV key pair...');
        const { cc, keyPair } = generateBGVContext(openfhe);
        console.log('BGV context created, keys generated');

        setLoading(true, 'Serializing public key...');
        const publicKeyBase64 = serializePublicKey(openfhe, keyPair.publicKey);
        console.log(`Public key serialized (${publicKeyBase64.length} bytes base64)`);

        setLoading(true, 'Registering with server...');
        const result = await registerPublicKey(publicKeyBase64);
        console.log('Registration successful:', result);

        setLoading(false);
        showResult(result.sessionId);

        cc.delete();

    } catch (error) {
        setLoading(false);
        showError(error);
    }
}

generateBtn.addEventListener('click', handleGenerateKey);

console.log('GenZ DNA Processing UI loaded');
