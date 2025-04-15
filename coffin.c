#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define AES_KEY_LENGTH 32
#define NONCE_LENGTH 12
#define MAC_LENGTH 16
#define HMAC_KEY_LENGTH 32
#define MAX_PATH_LENGTH 260
#define PBKDF2_ITERATIONS 100000
#define CHUNK_SIZE (1024 * 1024) // 1 MB

// Error handling macro
#define CHECK_STATUS(status, msg) if (!NT_SUCCESS(status)) { printf("Error: %s (0x%08x)\n", msg, status); goto cleanup; }

// Function to prompt for password (hidden input)
char* GetPassword() {
    char* password = (char*)malloc(100);
    if (!password) return NULL;
    printf("Enter password: ");
    char ch;
    int i = 0;
    while ((ch = _getch()) != '\r' && i < 99) {
        if (ch == '\b' && i > 0) {
            i--;
            printf("\b \b");
        } else if (ch != '\b') {
            password[i++] = ch;
            printf("*");
        }
    }
    password[i] = '\0';
    printf("\n");
    return password;
}

// Derive key using PBKDF2
NTSTATUS DeriveKey(const char* password, BYTE* key, DWORD keyLength) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    CHECK_STATUS(status, "Failed to open SHA256 provider");

    status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password, (ULONG)strlen(password), NULL, 0, PBKDF2_ITERATIONS, key, keyLength, 0);
    CHECK_STATUS(status, "Failed to derive key");

cleanup:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

// Compute HMAC-SHA256
NTSTATUS ComputeHMAC(const BYTE* data, DWORD dataLength, const BYTE* key, DWORD keyLength, BYTE* hmac, DWORD* hmacLength) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    CHECK_STATUS(status, "Failed to open HMAC provider");

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, keyLength, 0);
    CHECK_STATUS(status, "Failed to create HMAC hash");

    status = BCryptHashData(hHash, (PUCHAR)data, dataLength, 0);
    CHECK_STATUS(status, "Failed to hash data");

    status = BCryptFinishHash(hHash, hmac, *hmacLength, 0);
    CHECK_STATUS(status, "Failed to finish HMAC");

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

// Encrypt a file with streaming
NTSTATUS EncryptFile(const char* inputPath, const char* outputPath, const char* password, FILE* logFile) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BYTE key[AES_KEY_LENGTH], nonce[NONCE_LENGTH], hmacKey[HMAC_KEY_LENGTH];
    BYTE* buffer = NULL;
    FILE* fIn = NULL;
    FILE* fOut = NULL;
    DWORD bytesRead, totalBytes = 0, fileSize;

    // Derive keys
    status = DeriveKey(password, key, AES_KEY_LENGTH);
    CHECK_STATUS(status, "Key derivation failed");
    status = DeriveKey(password, hmacKey, HMAC_KEY_LENGTH);
    CHECK_STATUS(status, "HMAC key derivation failed");

    // Open AES-GCM
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    CHECK_STATUS(status, "Failed to open AES provider");
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    CHECK_STATUS(status, "Failed to set GCM mode");

    // Generate key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, AES_KEY_LENGTH, 0);
    CHECK_STATUS(status, "Failed to generate key");

    // Generate nonce
    status = BC
