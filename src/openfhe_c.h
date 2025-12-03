#ifndef OPENFHE_C_H
#define OPENFHE_C_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Error Handling
// ============================================================================

typedef enum {
    OPENFHE_OK = 0,
    OPENFHE_ERROR_NULL_POINTER = -1,
    OPENFHE_ERROR_INVALID_PARAM = -2,
    OPENFHE_ERROR_CRYPTO_FAILURE = -3,
    OPENFHE_ERROR_SERIALIZATION = -4,
    OPENFHE_ERROR_KEY_NOT_FOUND = -5,
    OPENFHE_ERROR_INTERNAL = -99
} OpenfheError;

// Get last error message (thread-local)
const char* openfhe_get_last_error(void);

// ============================================================================
// Opaque Pointer Types
// ============================================================================

typedef struct OpenfheCryptoContext* CryptoContextHandle;
typedef struct OpenfheKeyPair* KeyPairHandle;
typedef struct OpenfhePublicKey* PublicKeyHandle;
typedef struct OpenfhePrivateKey* PrivateKeyHandle;
typedef struct OpenfheCiphertext* CiphertextHandle;
typedef struct OpenfhePlaintext* PlaintextHandle;

// ============================================================================
// BGV Context Creation Parameters
// ============================================================================

typedef struct {
    uint32_t multiplicative_depth;
    uint64_t plaintext_modulus;
    uint32_t security_level;      // 128, 192, 256
    uint32_t ring_dim;            // 0 for auto
    uint32_t batch_size;          // 0 for auto
    uint32_t max_relin_sk_deg;    // default 2
    uint32_t first_mod_size;      // 0 for default
    uint32_t scaling_mod_size;    // 0 for default
    uint32_t num_large_digits;    // 0 for auto
} BgvParams;

// Initialize default BGV parameters
void bgv_params_default(BgvParams* params);

// ============================================================================
// Context Operations
// ============================================================================

// Create BGV crypto context
OpenfheError crypto_context_create_bgv(
    const BgvParams* params,
    CryptoContextHandle* out_ctx
);

// Enable features
OpenfheError crypto_context_enable_pke(CryptoContextHandle ctx);
OpenfheError crypto_context_enable_keyswitch(CryptoContextHandle ctx);
OpenfheError crypto_context_enable_leveledshe(CryptoContextHandle ctx);
OpenfheError crypto_context_enable_advancedshe(CryptoContextHandle ctx);
OpenfheError crypto_context_enable_fhe(CryptoContextHandle ctx);

// Get context parameters
uint32_t crypto_context_get_ring_dim(CryptoContextHandle ctx);
uint64_t crypto_context_get_plaintext_modulus(CryptoContextHandle ctx);
uint32_t crypto_context_get_cyclotomic_order(CryptoContextHandle ctx);

// Destroy context
void crypto_context_destroy(CryptoContextHandle ctx);

// ============================================================================
// Key Generation
// ============================================================================

// Generate key pair
OpenfheError keygen(CryptoContextHandle ctx, KeyPairHandle* out_keypair);

// Extract keys from keypair
PublicKeyHandle keypair_get_public_key(KeyPairHandle kp);
PrivateKeyHandle keypair_get_private_key(KeyPairHandle kp);

// Generate evaluation keys for multiplication
OpenfheError eval_mult_keys_gen(CryptoContextHandle ctx, PrivateKeyHandle sk);

// Generate evaluation keys for rotation
OpenfheError eval_rotate_keys_gen(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    const int32_t* indices,
    size_t num_indices
);

// Generate all rotation keys for sum
OpenfheError eval_sum_keys_gen(CryptoContextHandle ctx, PrivateKeyHandle sk);

// Destroy keys
void keypair_destroy(KeyPairHandle kp);
void public_key_destroy(PublicKeyHandle pk);
void private_key_destroy(PrivateKeyHandle sk);

// ============================================================================
// Plaintext Operations
// ============================================================================

// Create packed plaintext from int64 vector
OpenfheError make_packed_plaintext(
    CryptoContextHandle ctx,
    const int64_t* values,
    size_t length,
    PlaintextHandle* out_pt
);

// Create coefficient-packed plaintext
OpenfheError make_coef_packed_plaintext(
    CryptoContextHandle ctx,
    const int64_t* values,
    size_t length,
    PlaintextHandle* out_pt
);

// Get values from plaintext
OpenfheError plaintext_get_values(
    PlaintextHandle pt,
    int64_t* out_values,
    size_t* out_length,
    size_t max_length
);

// Set/get plaintext length
void plaintext_set_length(PlaintextHandle pt, size_t length);
size_t plaintext_get_length(PlaintextHandle pt);

// Destroy plaintext
void plaintext_destroy(PlaintextHandle pt);

// ============================================================================
// Encryption / Decryption
// ============================================================================

// Encrypt with public key
OpenfheError encrypt(
    CryptoContextHandle ctx,
    PublicKeyHandle pk,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
);

// Encrypt with private key
OpenfheError encrypt_private(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
);

// Decrypt
OpenfheError decrypt(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    CiphertextHandle ct,
    PlaintextHandle* out_pt
);

// ============================================================================
// Homomorphic Operations
// ============================================================================

// Addition
OpenfheError eval_add(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
);

OpenfheError eval_add_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2
);

OpenfheError eval_add_plaintext(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
);

// Subtraction
OpenfheError eval_sub(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
);

OpenfheError eval_sub_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2
);

// Multiplication
OpenfheError eval_mult(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
);

OpenfheError eval_mult_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2
);

OpenfheError eval_mult_no_relin(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    CiphertextHandle* out_ct
);

OpenfheError eval_mult_plaintext(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    PlaintextHandle pt,
    CiphertextHandle* out_ct
);

// Multiplication of many ciphertexts
OpenfheError eval_mult_many(
    CryptoContextHandle ctx,
    CiphertextHandle* cts,
    size_t num_cts,
    CiphertextHandle* out_ct
);

// Relinearization
OpenfheError eval_relinearize(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    CiphertextHandle* out_ct
);

// Negation
OpenfheError eval_negate(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    CiphertextHandle* out_ct
);

OpenfheError eval_negate_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct
);

// ============================================================================
// Rotation Operations
// ============================================================================

OpenfheError eval_rotate(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    int32_t index,
    CiphertextHandle* out_ct
);

OpenfheError eval_rotate_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    int32_t index
);

// Sum all slots
OpenfheError eval_sum(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    uint32_t batch_size,
    CiphertextHandle* out_ct
);

// Inner product
OpenfheError eval_inner_product(
    CryptoContextHandle ctx,
    CiphertextHandle ct1,
    CiphertextHandle ct2,
    uint32_t batch_size,
    CiphertextHandle* out_ct
);

// ============================================================================
// Level Operations (Mod-Reduce)
// ============================================================================

OpenfheError mod_reduce(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    CiphertextHandle* out_ct
);

OpenfheError mod_reduce_inplace(
    CryptoContextHandle ctx,
    CiphertextHandle ct
);

uint32_t ciphertext_get_level(CiphertextHandle ct);

// ============================================================================
// Bootstrapping (BGV)
// ============================================================================

OpenfheError eval_bootstrap_setup(
    CryptoContextHandle ctx,
    const uint32_t* level_budget,  // array of 2
    const uint32_t* dim1,          // array of 2, can be NULL
    uint32_t slots,
    uint32_t correction_factor
);

OpenfheError eval_bootstrap_keygen(
    CryptoContextHandle ctx,
    PrivateKeyHandle sk,
    uint32_t slots
);

OpenfheError eval_bootstrap(
    CryptoContextHandle ctx,
    CiphertextHandle ct,
    uint32_t num_iterations,
    uint32_t precision,
    CiphertextHandle* out_ct
);

// ============================================================================
// Serialization
// ============================================================================

typedef enum {
    SERIAL_BINARY = 0,
    SERIAL_JSON = 1
} SerialFormat;

// Context serialization
OpenfheError crypto_context_serialize(
    CryptoContextHandle ctx,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
);

OpenfheError crypto_context_deserialize(
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    CryptoContextHandle* out_ctx
);

// Public key serialization
OpenfheError public_key_serialize(
    PublicKeyHandle pk,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
);

OpenfheError public_key_deserialize(
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    PublicKeyHandle* out_pk
);

// Private key serialization
OpenfheError private_key_serialize(
    PrivateKeyHandle sk,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
);

OpenfheError private_key_deserialize(
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    PrivateKeyHandle* out_sk
);

// Ciphertext serialization
OpenfheError ciphertext_serialize(
    CiphertextHandle ct,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
);

OpenfheError ciphertext_deserialize(
    CryptoContextHandle ctx,
    const uint8_t* data,
    size_t size,
    SerialFormat format,
    CiphertextHandle* out_ct
);

// Eval keys serialization
OpenfheError eval_mult_keys_serialize(
    CryptoContextHandle ctx,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
);

OpenfheError eval_mult_keys_deserialize(
    CryptoContextHandle ctx,
    const uint8_t* data,
    size_t size,
    SerialFormat format
);

OpenfheError eval_automorphism_keys_serialize(
    CryptoContextHandle ctx,
    SerialFormat format,
    uint8_t** out_data,
    size_t* out_size
);

OpenfheError eval_automorphism_keys_deserialize(
    CryptoContextHandle ctx,
    const uint8_t* data,
    size_t size,
    SerialFormat format
);

// Free serialized data
void serialized_data_free(uint8_t* data);

// ============================================================================
// Ciphertext Management
// ============================================================================

CiphertextHandle ciphertext_clone(CiphertextHandle ct);
void ciphertext_destroy(CiphertextHandle ct);

#ifdef __cplusplus
}
#endif

#endif // OPENFHE_C_H
