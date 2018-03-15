#include "stdafx.h"
#include "EccTester.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <memory.h>

using namespace msclr::interop;
using namespace System::IO;
using namespace System::Security::Cryptography;
using namespace System::Security::Cryptography::X509Certificates;
using namespace System::Runtime::InteropServices;

struct _OpcUa_ByteString
{
	unsigned int Length;
	unsigned char* Data;
};

typedef struct _OpcUa_ByteString OpcUa_ByteString;

struct _OpcUa_Key
{
	unsigned int Type;
	OpcUa_ByteString Key;
};

typedef struct _OpcUa_Key OpcUa_Key;

static String^ FormatHexString(OpcUa_ByteString& bytes)
{
	auto buffer = gcnew System::Text::StringBuilder();

	for (unsigned int ii = 0; ii < bytes.Length; ii++)
	{
		buffer->AppendFormat("{0:X2}", bytes.Data[ii]);
	}

	return buffer->ToString();
}

static void PrintHexString(String^ text, OpcUa_ByteString& bytes)
{
	Console::WriteLine(text + " {0}", FormatHexString(bytes));
}

bool LoadCertificate(const char* filePath, OpcUa_ByteString* pCertificate)
{
	pCertificate->Length = 0;
	pCertificate->Data = nullptr;

	auto pFile = BIO_new_file(filePath, "rb");

	if (pFile == nullptr)
	{
		return false;
	}

	auto pX509 = d2i_X509_bio(pFile, (X509**)nullptr);

	if (pX509 == nullptr)
	{
		BIO_free(pFile);
		return false;
	}

	BIO_free(pFile);
	pFile = nullptr;

	pCertificate->Length = i2d_X509(pX509, NULL);
	auto pBuffer = pCertificate->Data = new unsigned char[pCertificate->Length];
	auto pos = pBuffer;
	
	auto result = i2d_X509(pX509, &pos);

	if (result != pCertificate->Length)
	{
		X509_free(pX509);
		return false;
	}

	X509_free(pX509);
	pX509 = nullptr;

	return true;
}

bool LoadPrivateKey(const char* filePath, const char* password, OpcUa_ByteString* pPrivateKey)
{
	pPrivateKey->Length = 0;
	pPrivateKey->Data = nullptr;

	auto pFile = BIO_new_file(filePath, "rb");

	if (pFile == nullptr)
	{
		return false;
	}

	auto pEvpKey = PEM_read_bio_PrivateKey(pFile, NULL, 0, (void*)password);

	if (pEvpKey == nullptr)
	{
		BIO_free(pFile);
		return false;
	}

	BIO_free(pFile);
	pFile = nullptr;

	auto pEcPrivateKey = EVP_PKEY_get1_EC_KEY(pEvpKey);

	if (pEcPrivateKey == nullptr)
	{
		EVP_PKEY_free(pEvpKey);
		return false;
	}

	EVP_PKEY_free(pEvpKey);
	pEvpKey = nullptr;

	pPrivateKey->Length = i2d_ECPrivateKey(pEcPrivateKey, nullptr);
	pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

	auto pData = pPrivateKey->Data;
	int result = i2d_ECPrivateKey(pEcPrivateKey, &pData);

	if (result != pPrivateKey->Length)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	EC_KEY_free(pEcPrivateKey);

	return true;
}

bool VerifySignature(
	OpcUa_ByteString* pData,
	OpcUa_ByteString* pCertificate)
{
	const unsigned char* pos = pCertificate->Data;

	auto pX509 = d2i_X509((X509**)nullptr, &pos, pCertificate->Length);

	if (pX509 == nullptr)
	{
		return false;
	}

	auto pX509PublicKey = X509_get_pubkey(pX509);

	if (pX509PublicKey == nullptr)
	{
		X509_free(pX509);
		return false;
	}

	auto pEcPublicKey = EVP_PKEY_get1_EC_KEY(pX509PublicKey);

	if (pEcPublicKey == nullptr)
	{
		X509_free(pX509);
		return false;
	}

	X509_free(pX509);
	pX509 = nullptr;

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPublicKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	OpcUa_ByteString signature;
	signature.Length = keySize*2;
	signature.Data = pData->Data + pData->Length - keySize*2;

	auto pEcSignature = ECDSA_SIG_new();

	if (pEcSignature == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	auto r = BN_bin2bn(signature.Data, keySize, nullptr);

	if (r == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	auto s = BN_bin2bn(signature.Data + keySize, keySize, nullptr);

	if (s == nullptr)
	{
		BN_free(r);
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	BN_free(pEcSignature->r);
	BN_free(pEcSignature->s);
	pEcSignature->r = r;
	pEcSignature->s = s;

	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (::SHA256(pData->Data, pData->Length - keySize*2, digest) == nullptr)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	if (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, pEcSignature, pEcPublicKey) != 1)
	{
		EC_KEY_free(pEcPublicKey);
		return false;
	}

	ECDSA_SIG_free(pEcSignature);
	EC_KEY_free(pEcPublicKey);

	return true;
}

#define bn2bin_pad(bn,to,len)                           \
    do {                                                \
        int pad_len = (len) - BN_num_bytes(bn);         \
        memset(to, 0, pad_len);                   \
        BN_bn2bin(bn, (to) + pad_len);                  \
    } while(0)

bool CreateSignature(
	OpcUa_ByteString* pData,
	OpcUa_ByteString* pPrivateKey,
	OpcUa_ByteString* pSignature)
{
	const unsigned char* pos = pPrivateKey->Data;

	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pos, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return false;
	}

	unsigned char digest[SHA256_DIGEST_LENGTH];

	if (::SHA256(pData->Data, pData->Length, digest) == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pEcSignature = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, pEcPrivateKey);

	if (pEcSignature == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	pSignature->Length = keySize * 2;
	pSignature->Data = new unsigned char[pSignature->Length];

	bn2bin_pad(pEcSignature->r, pSignature->Data, keySize);
	bn2bin_pad(pEcSignature->s, pSignature->Data + keySize, keySize);

	ECDSA_SIG_free(pEcSignature);
	EC_KEY_free(pEcPrivateKey);

	return true;
}

unsigned int GetSignatureSize(OpcUa_ByteString* pPrivateKey)
{
	const unsigned char* pos = pPrivateKey->Data;

	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pos, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return 0;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return 0;
	}

	keySize = (keySize + 7) / 8;
	EC_KEY_free(pEcPrivateKey);

	return keySize * 2;
}

static unsigned int DecodeUInt32(unsigned char* data, unsigned int offset, unsigned int length)
{
	if (data == nullptr || length < offset + 4)
	{
		return -1;
	}

	unsigned int value = data[offset];

	value += (((unsigned int)data[offset+1]) << 8);
	value += (((unsigned int)data[offset+2]) << 16);
	value += (((unsigned int)data[offset+3]) << 24);

	return value;
}

static void EncodeUInt32(unsigned int value, unsigned char* data, unsigned int offset, unsigned int length)
{
	if (data == nullptr || length < offset + 4)
	{
		return;
	}

	data[offset] = (unsigned char)(value & 0x000000FF);
	data[offset + 1] = (unsigned char)((value & 0x0000FF00) >> 8);
	data[offset + 2] = (unsigned char)((value & 0x00FF0000) >> 16);
	data[offset + 3] = (unsigned char)((value & 0xFF000000) >> 24);
}

static OpcUa_ByteString Copy(OpcUa_ByteString& src)
{
	OpcUa_ByteString dst;
	dst.Length = src.Length;
	dst.Data = new unsigned char[dst.Length];
	memcpy(dst.Data, src.Data, dst.Length);
	return dst;
}

static bool Decode(
	unsigned char* data, 
	unsigned int offset, 
	unsigned int length, 
	OpcUa_ByteString* pSenderCertificate, 
	OpcUa_ByteString* pSenderEphemeralKey)
{
	auto totalLength = DecodeUInt32(data, offset, length);

	auto signingCertificateLength = DecodeUInt32(data, offset + 4, length);
	auto pSigningCertificate = data + offset + 8;

	OpcUa_ByteString message;
	message.Data = data + offset;
	message.Length = totalLength;

	OpcUa_ByteString certificate;
	certificate.Data = pSigningCertificate;
	certificate.Length = signingCertificateLength;

	auto senderKeyLength = DecodeUInt32(data, offset + 8 + signingCertificateLength, length);
	auto pSenderKey = data + offset + 12 + signingCertificateLength;

	OpcUa_ByteString senderKey;
	senderKey.Data = pSenderKey;
	senderKey.Length = senderKeyLength;

	if (!VerifySignature(&message, &certificate))
	{
		return false;
	}

	*pSenderCertificate = Copy(certificate);
	*pSenderEphemeralKey = Copy(senderKey);

	PrintHexString("CLIENT EKEY", *pSenderEphemeralKey);
	return true;
}

static bool Encode(
	OpcUa_ByteString* pSenderCertificate,
	OpcUa_ByteString* pSenderPrivateKey,
	OpcUa_ByteString* pSenderEphemeralKey,
	OpcUa_ByteString* pMessage)
{
	auto totalLength = 12;
	totalLength += pSenderCertificate->Length;
	totalLength += pSenderEphemeralKey->Length;
	totalLength += GetSignatureSize(pSenderPrivateKey);

	pMessage->Length = totalLength;
	pMessage->Data = new unsigned char[totalLength];

	auto offset = 0;
	EncodeUInt32(totalLength, pMessage->Data, offset, pMessage->Length);

	offset += 4;
	EncodeUInt32(pSenderCertificate->Length, pMessage->Data, offset, pMessage->Length);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderCertificate->Data, pSenderCertificate->Length);

	offset += pSenderCertificate->Length;
	EncodeUInt32(pSenderEphemeralKey->Length, pMessage->Data, offset, pMessage->Length);

	offset += 4;
	memcpy(pMessage->Data + offset, pSenderEphemeralKey->Data, pSenderEphemeralKey->Length);

	offset += pSenderEphemeralKey->Length;
	PrintHexString("SERVER EKEY", *pSenderEphemeralKey);

	OpcUa_ByteString message;
	message.Data = pMessage->Data;
	message.Length = offset;

	OpcUa_ByteString signature;
	signature.Data = nullptr;
	signature.Length = 0;

	if (!CreateSignature(&message, pSenderPrivateKey, &signature))
	{
		delete[] pMessage->Data;
		pMessage->Data = nullptr;
		pMessage->Length = 0;
		return false;
	}

	memcpy(pMessage->Data + offset, signature.Data, signature.Length);
	delete[] signature.Data;

	return true;
}

bool GenerateKeys(
	const char* curveName,
	OpcUa_ByteString* pPublicKey,
	OpcUa_ByteString* pPrivateKey)
{
	pPublicKey->Length = 0;
	pPublicKey->Data = nullptr;

	pPrivateKey->Length = 0;
	pPrivateKey->Data = nullptr;

	int curveId = 0;

	if (strcmp(SN_X9_62_prime256v1, curveName) == 0)
	{
		curveId = NID_X9_62_prime256v1;
	}

	auto pEcKey = EC_KEY_new_by_curve_name(curveId);

	if (pEcKey == nullptr)
	{
		return false;
	}

	if (EC_KEY_generate_key(pEcKey) == 0)
	{
		EC_KEY_free(pEcKey);
		return false;
	}

	pPrivateKey->Length = i2d_ECPrivateKey(pEcKey, NULL);

	if (pPrivateKey->Length == 0)
	{
		EC_KEY_free(pEcKey);
		return false;
	}

	pPrivateKey->Data = new unsigned char[pPrivateKey->Length];

	if (pPrivateKey->Data == nullptr)
	{
		EC_KEY_free(pEcKey);
		return false; 
	}

	auto pData = pPrivateKey->Data;
	pPrivateKey->Length = i2d_ECPrivateKey(pEcKey, &pData);

	if (pPrivateKey->Length == 0)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcKey));

	if (keySize == 0)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	pPublicKey->Length = keySize * 2;
	pPublicKey->Data = new unsigned char[pPublicKey->Length];

	if (pPublicKey->Data == nullptr)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto pCtx = BN_CTX_new();

	if (pCtx == nullptr)
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		delete[] pPublicKey->Data;
		pPublicKey->Data = nullptr;
		pPublicKey->Length = 0;
		EC_KEY_free(pEcKey);
		return false;
	}

	auto x = BN_CTX_get(pCtx);
	auto y = BN_CTX_get(pCtx);

	auto point = EC_KEY_get0_public_key(pEcKey);

	if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcKey), point, x, y, pCtx))
	{
		delete[] pPrivateKey->Data;
		pPrivateKey->Data = nullptr;
		pPrivateKey->Length = 0;
		delete[] pPublicKey->Data;
		pPublicKey->Data = nullptr;
		pPublicKey->Length = 0;
		EC_KEY_free(pEcKey);
		BN_CTX_free(pCtx);
		return false;
	}

	bn2bin_pad(x, pPublicKey->Data, keySize);
	bn2bin_pad(y, pPublicKey->Data + keySize, keySize);

	BN_CTX_free(pCtx);
	EC_KEY_free(pEcKey);
	return true;
}

bool ComputeSecret(
	OpcUa_ByteString* pNonce,
	OpcUa_ByteString* pPrivateKey,
	OpcUa_ByteString* pSharedSecret)
{
	const unsigned char* pData = pPrivateKey->Data;
	auto pEcPrivateKey = d2i_ECPrivateKey(nullptr, &pData, pPrivateKey->Length);

	if (pEcPrivateKey == nullptr)
	{
		return false;
	}

	auto keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));

	if (keySize == 0)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	keySize = (keySize + 7) / 8;

	if (pNonce->Length != 2 * keySize)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pCtx = BN_CTX_new();

	if (pCtx == nullptr)
	{
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto x = BN_CTX_get(pCtx);
	auto y = BN_CTX_get(pCtx);

	x = BN_bin2bn(pNonce->Data, keySize, x);

	if (x == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	y = BN_bin2bn(pNonce->Data + keySize, keySize, y);

	if (y == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto p1 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));

	if (p1 == nullptr)
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey), p1, x, y, pCtx))
	{
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto p2 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));

	if (p2 == nullptr)
	{
		EC_POINT_free(p1);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_mul(EC_KEY_get0_group(pEcPrivateKey), p2, NULL, p1, EC_KEY_get0_private_key(pEcPrivateKey), pCtx))
	{
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey), p2, x, y, pCtx))
	{
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	auto pBuffer = new unsigned char[keySize];
	memset(pBuffer, 0, keySize);
	bn2bin_pad(x, pBuffer, keySize);
	// bn2bin_pad(y, pBuffer + keySize, keySize);
	    
	pSharedSecret->Length = SHA512_DIGEST_LENGTH;
	pSharedSecret->Data = new unsigned char[SHA512_DIGEST_LENGTH];

	/*
	unsigned char key = 1;

	if (::HMAC(EVP_sha512(), &key, 1, pBuffer, keySize, pSharedSecret->Data, (unsigned int*)&pSharedSecret->Length) == nullptr)
	{
		delete[] pSharedSecret->Data;
		pSharedSecret->Data = nullptr;
		pSharedSecret->Length = 0;
		delete[] pBuffer;
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}
	*/

	if (::SHA512(pBuffer, keySize, pSharedSecret->Data) == nullptr)
	{
		delete[] pSharedSecret->Data;
		pSharedSecret->Data = nullptr;
		pSharedSecret->Length = 0;
		delete[] pBuffer;
		EC_POINT_free(p1);
		EC_POINT_free(p2);
		BN_CTX_free(pCtx);
		EC_KEY_free(pEcPrivateKey);
		return false;
	}

	delete[] pBuffer;
	EC_POINT_free(p1);
	EC_POINT_free(p2);
	BN_CTX_free(pCtx);
	EC_KEY_free(pEcPrivateKey);

	return true;
}

static bool AreEqual(OpcUa_ByteString& value1, OpcUa_ByteString& value2)
{
	if (value2.Length != value1.Length)
	{
		return false;
	}

	for (auto ii = 0U; ii < value1.Length; ii++)
	{
		if (value1.Data[ii] != value2.Data[ii])
		{
			return false;
		}
	}

	return true;
}

namespace EccOpenSsl {

	class EccTesterData
	{
	public:

		EccTesterData()
		{
			memset(&Certificate, 0, sizeof(OpcUa_ByteString));
			memset(&PrivateKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPublicKey, 0, sizeof(OpcUa_ByteString));
			memset(&EphemeralPrivateKey, 0, sizeof(OpcUa_ByteString));
		}

		~EccTesterData()
		{
			if (Certificate.Data != nullptr)
			{
				delete[] Certificate.Data;
			}

			if (PrivateKey.Data != nullptr)
			{
				delete[] PrivateKey.Data;
			}

			if (EphemeralPublicKey.Data != nullptr)
			{
				delete[] EphemeralPublicKey.Data;
			}

			if (EphemeralPrivateKey.Data != nullptr)
			{
				delete[] EphemeralPrivateKey.Data;
			}
		}

		OpcUa_ByteString Certificate;
		OpcUa_ByteString PrivateKey;
		OpcUa_ByteString EphemeralPublicKey;
		OpcUa_ByteString EphemeralPrivateKey;
	};

	EccTester::EccTester()
	{
		m_p = new EccTesterData();
	}

	EccTester::~EccTester()
	{
		delete m_p;
	}

	void EccTester::SetLocalCertificate(String^ certificateFilePath, String^ privateKeyFilePath, String^ password)
	{
		marshal_context context;
		auto pFilePath = context.marshal_as<const char*>(certificateFilePath);

		if (!LoadCertificate(pFilePath, &m_p->Certificate))
		{
			throw gcnew ArgumentException("certificateFilePath");
		}

		pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
		auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

		if (!LoadPrivateKey(pFilePath, pPassword, &m_p->PrivateKey))
		{
			throw gcnew ArgumentException("privateKeyFilePath");
		}
	}

	array<unsigned char>^ EccTester::Decode(String^ requestPath, String^ responsePath)
	{
		auto bytes = File::ReadAllBytes(requestPath);

		auto message = new unsigned char[bytes->Length];
		OpcUa_ByteString senderCertificate;
		OpcUa_ByteString senderEphemeralPublicKey;
		OpcUa_ByteString response;
		OpcUa_ByteString sharedSecret;

		try
		{
			Marshal::Copy(bytes, 0, (IntPtr)message, bytes->Length);

			if (!::Decode(message, 0, bytes->Length, &senderCertificate, &senderEphemeralPublicKey))
			{
				throw gcnew ArgumentException("messagePath");
			}

			if (!GenerateKeys(SN_X9_62_prime256v1, &m_p->EphemeralPublicKey, &m_p->EphemeralPrivateKey))
			{
				throw gcnew ArgumentException("generateKeys");
			}

			if (!ComputeSecret(&senderEphemeralPublicKey, &m_p->EphemeralPrivateKey, &sharedSecret))
			{
				throw gcnew ArgumentException("computeSecret");
			}

			// do a sanity check by deriving key using OpenSSL APIs. They match.
			{
				OpcUa_ByteString sanityPublicKey;
				OpcUa_ByteString sanityPrivateKy;

				if (!GenerateKeys(SN_X9_62_prime256v1, &sanityPublicKey, &sanityPrivateKy))
				{
					throw gcnew ArgumentException("generateKeys");
				}

				OpcUa_ByteString sharedKey3;

				if (!ComputeSecret(&m_p->EphemeralPublicKey, &sanityPrivateKy, &sharedKey3))
				{
					throw gcnew ArgumentException("computeSecret");
				}

				OpcUa_ByteString sharedKey4;

				if (!ComputeSecret(&sanityPublicKey, &m_p->EphemeralPrivateKey, &sharedKey4))
				{
					throw gcnew ArgumentException("computeSecret");
				}

				if (!AreEqual(sharedKey3, sharedKey4))
				{
					throw gcnew ArgumentException("sanityCkeckFailed");
				}
			}

			if (!::Encode(&m_p->Certificate, &m_p->PrivateKey, &m_p->EphemeralPublicKey, &response))
			{
				throw gcnew ArgumentException("encode");
			}

			bytes = gcnew array<unsigned char>(response.Length);
			Marshal::Copy((IntPtr)response.Data, bytes, 0, bytes->Length);
			File::WriteAllBytes(responsePath, bytes);

			bytes = gcnew array<unsigned char>(sharedSecret.Length);
			Marshal::Copy((IntPtr)sharedSecret.Data, bytes, 0, bytes->Length);
			return bytes;
		}
		finally
		{
			delete[] message;
			delete[] senderCertificate.Data;
			delete[] senderEphemeralPublicKey.Data;
			delete[] sharedSecret.Data;
		}
	}

	void EccTester::Encode(String^ certificateFilePath, String^ privateKeyFilePath, String^ password)
	{
		marshal_context context;
		auto pFilePath = context.marshal_as<const char*>(certificateFilePath);

		OpcUa_ByteString certificate;
		OpcUa_ByteString privateKey;

		if (!LoadCertificate(pFilePath, &certificate))
		{
			throw gcnew ArgumentException("keyFilePath");
		}

		pFilePath = context.marshal_as<const char*>(privateKeyFilePath);
		auto pPassword = (password != nullptr) ? context.marshal_as<const char*>(password) : nullptr;

		if (!LoadPrivateKey(pFilePath, pPassword, &privateKey))
		{
			throw gcnew ArgumentException("keyFilePath");
		}
	}

	void EccTester::Initialize()
	{
		OpenSSL_add_all_algorithms();
		RAND_screen();
		SSL_library_init();
		SSL_load_error_strings();
	}

	void EccTester::Cleanup()
	{
		SSL_COMP_free_compression_methods();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
		ERR_remove_state(0);
		ERR_free_strings();
	}
}