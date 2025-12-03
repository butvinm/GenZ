#include "openfhe_c.h"
#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

#include <memory>
#include <string>
#include <sstream>
#include <cstring>
#include <algorithm>

using namespace lbcrypto;

// Thread-local error message storage
static thread_local std::string g_last_error;

// ============================================================================
// Internal Wrapper Structures
// ============================================================================

struct OpenfheCryptoContext {
    CryptoContext<DCRTPoly> ctx;

    explicit OpenfheCryptoContext(CryptoContext<DCRTPoly> c) : ctx(std::move(c)) {}
};

struct OpenfheKeyPair {
    KeyPair<DCRTPoly> kp;

    explicit OpenfheKeyPair(KeyPair<DCRTPoly> k) : kp(std::move(k)) {}
};

struct OpenfhePublicKey {
    PublicKey<DCRTPoly> key;
    bool owned;

    explicit OpenfhePublicKey(PublicKey<DCRTPoly> k, bool o = true)
        : key(std::move(k)), owned(o) {}
};

struct OpenfhePrivateKey {
    PrivateKey<DCRTPoly> key;
    bool owned;

    explicit OpenfhePrivateKey(PrivateKey<DCRTPoly> k, bool o = true)
        : key(std::move(k)), owned(o) {}
};

struct OpenfheCiphertext {
    Ciphertext<DCRTPoly> ct;

    explicit OpenfheCiphertext(Ciphertext<DCRTPoly> c) : ct(std::move(c)) {}
};

struct OpenfhePlaintext {
    Plaintext pt;

    explicit OpenfhePlaintext(Plaintext p) : pt(std::move(p)) {}
};

// ============================================================================
// Error Handling Implementation
// ============================================================================

static void set_error(const std::string& msg) {
    g_last_error = msg;
}

extern "C" const char* openfhe_get_last_error(void) {
    return g_last_error.c_str();
}

// Macro for exception handling
#define TRY_CATCH_BEGIN try {
#define TRY_CATCH_END \
    return OPENFHE_OK; \
    } catch (const std::exception& e) { \
        set_error(e.what()); \
        return OPENFHE_ERROR_INTERNAL; \
    } catch (...) { \
        set_error("Unknown error"); \
        return OPENFHE_ERROR_INTERNAL; \
    }

// ============================================================================
// Context Operations Implementation
// ============================================================================

extern "C" void bgv_params_default(BgvParams* params) {
    if (!params) return;
    params->multiplicative_depth = 2;
    params->plaintext_modulus = 65537;
    params->security_level = 128;
    params->ring_dim = 0;
    params->batch_size = 0;
    params->max_relin_sk_deg = 2;
    params->first_mod_size = 0;
    params->scaling_mod_size = 0;
    params->num_large_digits = 0;
}

extern "C" OpenfheError crypto_context_create_bgv(
    const BgvParams* params,
    CryptoContextHandle* out_ctx
) {
    if (!params || !out_ctx) {
        set_error("Null pointer argument");
        return OPENFHE_ERROR_NULL_POINTER;
    }

    TRY_CATCH_BEGIN
        CCParams<CryptoContextBGVRNS> cc_params;
        cc_params.SetMultiplicativeDepth(params->multiplicative_depth);
        cc_params.SetPlaintextModulus(params->plaintext_modulus);

        // Map security level
        SecurityLevel sec_level = HEStd_128_classic;
        switch (params->security_level) {
            case 192: sec_level = HEStd_192_classic; break;
            case 256: sec_level = HEStd_256_classic; break;
            default: sec_level = HEStd_128_classic; break;
        }
        cc_params.SetSecurityLevel(sec_level);

        if (params->ring_dim > 0)
            cc_params.SetRingDim(params->ring_dim);
        if (params->batch_size > 0)
            cc_params.SetBatchSize(params->batch_size);
        if (params->max_relin_sk_deg > 0)
            cc_params.SetMaxRelinSkDeg(params->max_relin_sk_deg);
        if (params->first_mod_size > 0)
            cc_params.SetFirstModSize(params->first_mod_size);
        if (params->scaling_mod_size > 0)
            cc_params.SetScalingModSize(params->scaling_mod_size);
        if (params->num_large_digits > 0)
            cc_params.SetNumLargeDigits(params->num_large_digits);

        auto ctx = GenCryptoContext(cc_params);
        *out_ctx = new OpenfheCryptoContext(ctx);
    TRY_CATCH_END
}

extern "C" OpenfheError crypto_context_enable_pke(CryptoContextHandle ctx) {
    if (!ctx) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->Enable(PKE);
    TRY_CATCH_END
}

extern "C" OpenfheError crypto_context_enable_keyswitch(CryptoContextHandle ctx) {
    if (!ctx) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->Enable(KEYSWITCH);
    TRY_CATCH_END
}

extern "C" OpenfheError crypto_context_enable_leveledshe(CryptoContextHandle ctx) {
    if (!ctx) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->Enable(LEVELEDSHE);
    TRY_CATCH_END
}

extern "C" OpenfheError crypto_context_enable_advancedshe(CryptoContextHandle ctx) {
    if (!ctx) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->Enable(ADVANCEDSHE);
    TRY_CATCH_END
}

extern "C" OpenfheError crypto_context_enable_fhe(CryptoContextHandle ctx) {
    if (!ctx) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->Enable(FHE);
    TRY_CATCH_END
}

extern "C" uint32_t crypto_context_get_ring_dim(CryptoContextHandle ctx) {
    if (!ctx) return 0;
    return ctx->ctx->GetRingDimension();
}

extern "C" uint64_t crypto_context_get_plaintext_modulus(CryptoContextHandle ctx) {
    if (!ctx) return 0;
    return ctx->ctx->GetCryptoParameters()->GetPlaintextModulus();
}

extern "C" uint32_t crypto_context_get_cyclotomic_order(CryptoContextHandle ctx) {
    if (!ctx) return 0;
    return ctx->ctx->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
}

extern "C" void crypto_context_destroy(CryptoContextHandle ctx) {
    delete ctx;
}

// ============================================================================
// Key Generation Implementation
// ============================================================================

extern "C" OpenfheError keygen(CryptoContextHandle ctx, KeyPairHandle* out_keypair) {
    if (!ctx || !out_keypair) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto kp = ctx->ctx->KeyGen();
        if (!kp.good()) {
            set_error("Key generation failed");
            return OPENFHE_ERROR_CRYPTO_FAILURE;
        }
        *out_keypair = new OpenfheKeyPair(kp);
    TRY_CATCH_END
}

extern "C" PublicKeyHandle keypair_get_public_key(KeyPairHandle kp) {
    if (!kp) return nullptr;
    return new OpenfhePublicKey(kp->kp.publicKey, false);
}

extern "C" PrivateKeyHandle keypair_get_private_key(KeyPairHandle kp) {
    if (!kp) return nullptr;
    return new OpenfhePrivateKey(kp->kp.secretKey, false);
}

extern "C" OpenfheError eval_mult_keys_gen(CryptoContextHandle ctx, PrivateKeyHandle sk) {
    if (!ctx || !sk) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->EvalMultKeyGen(sk->key);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_rotate_keys_gen(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    const int32_t* indices,
    size_t num_indices
) {
    if (!ctx || !sk || !indices) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::vector<int32_t> index_list(indices, indices + num_indices);
        ctx->ctx->EvalRotateKeyGen(sk->key, index_list);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_sum_keys_gen(CryptoContextHandle ctx, PrivateKeyHandle sk) {
    if (!ctx || !sk) return OPENFHE_ERROR_NULL_POINTER;
    TRY_CATCH_BEGIN
        ctx->ctx->EvalSumKeyGen(sk->key);
    TRY_CATCH_END
}

extern "C" void keypair_destroy(KeyPairHandle kp) {
    delete kp;
}

extern "C" void public_key_destroy(PublicKeyHandle pk) {
    delete pk;
}

extern "C" void private_key_destroy(PrivateKeyHandle sk) {
    delete sk;
}

// ============================================================================
// Plaintext Operations Implementation
// ============================================================================

extern "C" OpenfheError make_packed_plaintext(
    CryptoContextHandle ctx,
    const int64_t* values,
    size_t length,
    PlaintextHandle* out_pt
) {
    if (!ctx || !values || !out_pt) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::vector<int64_t> vec(values, values + length);
        auto pt = ctx->ctx->MakePackedPlaintext(vec);
        *out_pt = new OpenfhePlaintext(pt);
    TRY_CATCH_END
}

extern "C" OpenfheError make_coef_packed_plaintext(
    CryptoContextHandle ctx,
    const int64_t* values,
    size_t length,
    PlaintextHandle* out_pt
) {
    if (!ctx || !values || !out_pt) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::vector<int64_t> vec(values, values + length);
        auto pt = ctx->ctx->MakeCoefPackedPlaintext(vec);
        *out_pt = new OpenfhePlaintext(pt);
    TRY_CATCH_END
}

extern "C" OpenfheError plaintext_get_values(
    PlaintextHandle pt,
    int64_t* out_values,
    size_t* out_length,
    size_t max_length
) {
    if (!pt || !out_values || !out_length) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto packed = pt->pt->GetPackedValue();
        *out_length = std::min(packed.size(), max_length);
        std::copy(packed.begin(), packed.begin() + *out_length, out_values);
    TRY_CATCH_END
}

extern "C" void plaintext_set_length(PlaintextHandle pt, size_t length) {
    if (pt) pt->pt->SetLength(length);
}

extern "C" size_t plaintext_get_length(PlaintextHandle pt) {
    return pt ? pt->pt->GetLength() : 0;
}

extern "C" void plaintext_destroy(PlaintextHandle pt) {
    delete pt;
}

// ============================================================================
// Encryption / Decryption Implementation
// ============================================================================

extern "C" OpenfheError encrypt(
    CryptoContextHandle ctx,
    PublicKeyHandle pk,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
) {
    if (!ctx || !pk || !pt || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto ct = ctx->ctx->Encrypt(pk->key, pt->pt);
        *out_ct = new OpenfheCiphertext(ct);
    TRY_CATCH_END
}

extern "C" OpenfheError encrypt_private(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
) {
    if (!ctx || !sk || !pt || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto ct = ctx->ctx->Encrypt(sk->key, pt->pt);
        *out_ct = new OpenfheCiphertext(ct);
    TRY_CATCH_END
}

extern "C" OpenfheError decrypt(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    CiphertextHandle ct,
    PlaintextHandle* out_pt
) {
    if (!ctx || !sk || !ct || !out_pt) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        Plaintext pt;
        ctx->ctx->Decrypt(sk->key, ct->ct, &pt);
        *out_pt = new OpenfhePlaintext(pt);
    TRY_CATCH_END
}

// ============================================================================
// Homomorphic Operations Implementation
// ============================================================================

extern "C" OpenfheError eval_add(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct1 || !ct2 || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalAdd(ct1->ct, ct2->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_add_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2
) {
    if (!ctx || !ct1 || !ct2) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        ctx->ctx->EvalAddInPlace(ct1->ct, ct2->ct);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_add_plaintext(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !pt || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalAdd(ct->ct, pt->pt);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_sub(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct1 || !ct2 || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalSub(ct1->ct, ct2->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_sub_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2
) {
    if (!ctx || !ct1 || !ct2) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        ctx->ctx->EvalSubInPlace(ct1->ct, ct2->ct);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct1 || !ct2 || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalMult(ct1->ct, ct2->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2
) {
    if (!ctx || !ct1 || !ct2) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        // OpenFHE doesn't have in-place mult for two ciphertexts, so we do it manually
        ct1->ct = ctx->ctx->EvalMult(ct1->ct, ct2->ct);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult_no_relin(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct1 || !ct2 || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalMultNoRelin(ct1->ct, ct2->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult_plaintext(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !pt || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalMult(ct->ct, pt->pt);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult_many(
    CryptoContextHandle ctx,
    CiphertextHandle* cts,
    size_t num_cts,
    CiphertextHandle* out_ct
) {
    if (!ctx || !cts || !out_ct || num_cts == 0) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::vector<Ciphertext<DCRTPoly>> ct_vec;
        ct_vec.reserve(num_cts);
        for (size_t i = 0; i < num_cts; ++i) {
            if (!cts[i]) return OPENFHE_ERROR_NULL_POINTER;
            ct_vec.push_back(cts[i]->ct);
        }
        auto result = ctx->ctx->EvalMultMany(ct_vec);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_relinearize(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->Relinearize(ct->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_negate(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalNegate(ct->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_negate_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct
) {
    if (!ctx || !ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        ctx->ctx->EvalNegateInPlace(ct->ct);
    TRY_CATCH_END
}

// ============================================================================
// Rotation Operations Implementation
// ============================================================================

extern "C" OpenfheError eval_rotate(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    int32_t index,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalRotate(ct->ct, index);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_rotate_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    int32_t index
) {
    if (!ctx || !ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        // OpenFHE doesn't have in-place rotate, so we do it manually
        ct->ct = ctx->ctx->EvalRotate(ct->ct, index);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_sum(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    uint32_t batch_size,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalSum(ct->ct, batch_size);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_inner_product(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    uint32_t batch_size,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct1 || !ct2 || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalInnerProduct(ct1->ct, ct2->ct, batch_size);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

// ============================================================================
// Level Operations Implementation
// ============================================================================

extern "C" OpenfheError mod_reduce(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->ModReduce(ct->ct);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

extern "C" OpenfheError mod_reduce_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct
) {
    if (!ctx || !ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        ctx->ctx->ModReduceInPlace(ct->ct);
    TRY_CATCH_END
}

extern "C" uint32_t ciphertext_get_level(CiphertextHandle ct) {
    return ct ? ct->ct->GetLevel() : 0;
}

// ============================================================================
// Bootstrapping Implementation
// ============================================================================

extern "C" OpenfheError eval_bootstrap_setup(
    CryptoContextHandle ctx,
    const uint32_t* level_budget,
    const uint32_t* dim1,
    uint32_t slots,
    uint32_t correction_factor
) {
    if (!ctx || !level_budget) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::vector<uint32_t> lb = {level_budget[0], level_budget[1]};
        std::vector<uint32_t> d1;
        if (dim1) {
            d1 = {dim1[0], dim1[1]};
        }
        ctx->ctx->EvalBootstrapSetup(lb, d1, slots, correction_factor);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_bootstrap_keygen(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    uint32_t slots
) {
    if (!ctx || !sk) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        ctx->ctx->EvalBootstrapKeyGen(sk->key, slots);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_bootstrap(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    uint32_t num_iterations,
    uint32_t precision,
    CiphertextHandle* out_ct
) {
    if (!ctx || !ct || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        auto result = ctx->ctx->EvalBootstrap(ct->ct, num_iterations, precision);
        *out_ct = new OpenfheCiphertext(result);
    TRY_CATCH_END
}

// ============================================================================
// Serialization Implementation
// ============================================================================

extern "C" OpenfheError crypto_context_serialize(
    CryptoContextHandle ctx,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
) {
    if (!ctx || !out_data || !out_size) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::stringstream ss;
        if (format == SERIAL_BINARY) {
            Serial::Serialize(ctx->ctx, ss, SerType::BINARY);
        } else {
            Serial::Serialize(ctx->ctx, ss, SerType::JSON);
        }

        std::string data = ss.str();
        *out_size = data.size();
        *out_data = new uint8_t[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    TRY_CATCH_END
}

extern "C" OpenfheError crypto_context_deserialize(
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    CryptoContextHandle* out_ctx
) {
    if (!data || !out_ctx) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::string str(reinterpret_cast<const char*>(data), size);
        std::stringstream ss(str);

        CryptoContext<DCRTPoly> ctx;
        if (format == SERIAL_BINARY) {
            Serial::Deserialize(ctx, ss, SerType::BINARY);
        } else {
            Serial::Deserialize(ctx, ss, SerType::JSON);
        }

        *out_ctx = new OpenfheCryptoContext(ctx);
    TRY_CATCH_END
}

extern "C" OpenfheError public_key_serialize(
    PublicKeyHandle pk,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
) {
    if (!pk || !out_data || !out_size) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::stringstream ss;
        if (format == SERIAL_BINARY) {
            Serial::Serialize(pk->key, ss, SerType::BINARY);
        } else {
            Serial::Serialize(pk->key, ss, SerType::JSON);
        }

        std::string data = ss.str();
        *out_size = data.size();
        *out_data = new uint8_t[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    TRY_CATCH_END
}

extern "C" OpenfheError public_key_deserialize(
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    PublicKeyHandle* out_pk
) {
    if (!data || !out_pk) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::string str(reinterpret_cast<const char*>(data), size);
        std::stringstream ss(str);

        PublicKey<DCRTPoly> pk;
        if (format == SERIAL_BINARY) {
            Serial::Deserialize(pk, ss, SerType::BINARY);
        } else {
            Serial::Deserialize(pk, ss, SerType::JSON);
        }

        *out_pk = new OpenfhePublicKey(pk);
    TRY_CATCH_END
}

extern "C" OpenfheError private_key_serialize(
    PrivateKeyHandle sk,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
) {
    if (!sk || !out_data || !out_size) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::stringstream ss;
        if (format == SERIAL_BINARY) {
            Serial::Serialize(sk->key, ss, SerType::BINARY);
        } else {
            Serial::Serialize(sk->key, ss, SerType::JSON);
        }

        std::string data = ss.str();
        *out_size = data.size();
        *out_data = new uint8_t[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    TRY_CATCH_END
}

extern "C" OpenfheError private_key_deserialize(
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    PrivateKeyHandle* out_sk
) {
    if (!data || !out_sk) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::string str(reinterpret_cast<const char*>(data), size);
        std::stringstream ss(str);

        PrivateKey<DCRTPoly> sk;
        if (format == SERIAL_BINARY) {
            Serial::Deserialize(sk, ss, SerType::BINARY);
        } else {
            Serial::Deserialize(sk, ss, SerType::JSON);
        }

        *out_sk = new OpenfhePrivateKey(sk);
    TRY_CATCH_END
}

extern "C" OpenfheError ciphertext_serialize(
    CiphertextHandle ct,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
) {
    if (!ct || !out_data || !out_size) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::stringstream ss;
        if (format == SERIAL_BINARY) {
            Serial::Serialize(ct->ct, ss, SerType::BINARY);
        } else {
            Serial::Serialize(ct->ct, ss, SerType::JSON);
        }

        std::string data = ss.str();
        *out_size = data.size();
        *out_data = new uint8_t[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    TRY_CATCH_END
}

extern "C" OpenfheError ciphertext_deserialize(
    CryptoContextHandle ctx,
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    CiphertextHandle* out_ct
) {
    if (!ctx || !data || !out_ct) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::string str(reinterpret_cast<const char*>(data), size);
        std::stringstream ss(str);

        Ciphertext<DCRTPoly> ct;
        if (format == SERIAL_BINARY) {
            Serial::Deserialize(ct, ss, SerType::BINARY);
        } else {
            Serial::Deserialize(ct, ss, SerType::JSON);
        }

        *out_ct = new OpenfheCiphertext(ct);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult_keys_serialize(
    CryptoContextHandle ctx,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
) {
    if (!ctx || !out_data || !out_size) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::stringstream ss;
        if (format == SERIAL_BINARY) {
            ctx->ctx->SerializeEvalMultKey(ss, SerType::BINARY);
        } else {
            ctx->ctx->SerializeEvalMultKey(ss, SerType::JSON);
        }

        std::string data = ss.str();
        *out_size = data.size();
        *out_data = new uint8_t[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_mult_keys_deserialize(
    CryptoContextHandle ctx,
    const uint8_t* data,
    size_t size,
    SerialFormat format
) {
    if (!ctx || !data) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::string str(reinterpret_cast<const char*>(data), size);
        std::stringstream ss(str);

        if (format == SERIAL_BINARY) {
            ctx->ctx->DeserializeEvalMultKey(ss, SerType::BINARY);
        } else {
            ctx->ctx->DeserializeEvalMultKey(ss, SerType::JSON);
        }
    TRY_CATCH_END
}

extern "C" OpenfheError eval_automorphism_keys_serialize(
    CryptoContextHandle ctx,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
) {
    if (!ctx || !out_data || !out_size) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::stringstream ss;
        if (format == SERIAL_BINARY) {
            ctx->ctx->SerializeEvalAutomorphismKey(ss, SerType::BINARY);
        } else {
            ctx->ctx->SerializeEvalAutomorphismKey(ss, SerType::JSON);
        }

        std::string data = ss.str();
        *out_size = data.size();
        *out_data = new uint8_t[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    TRY_CATCH_END
}

extern "C" OpenfheError eval_automorphism_keys_deserialize(
    CryptoContextHandle ctx,
    const uint8_t* data,
    size_t size,
    SerialFormat format
) {
    if (!ctx || !data) return OPENFHE_ERROR_NULL_POINTER;

    TRY_CATCH_BEGIN
        std::string str(reinterpret_cast<const char*>(data), size);
        std::stringstream ss(str);

        if (format == SERIAL_BINARY) {
            ctx->ctx->DeserializeEvalAutomorphismKey(ss, SerType::BINARY);
        } else {
            ctx->ctx->DeserializeEvalAutomorphismKey(ss, SerType::JSON);
        }
    TRY_CATCH_END
}

extern "C" void serialized_data_free(uint8_t* data) {
    delete[] data;
}

// ============================================================================
// Ciphertext Management Implementation
// ============================================================================

extern "C" CiphertextHandle ciphertext_clone(CiphertextHandle ct) {
    if (!ct) return nullptr;
    return new OpenfheCiphertext(ct->ct->Clone());
}

extern "C" void ciphertext_destroy(CiphertextHandle ct) {
    delete ct;
}
