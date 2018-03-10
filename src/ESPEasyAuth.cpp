/*
 * ESP EasyAuth
 * Zhenyu Wu (Adam_5Wu@hotmail.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.	If not, see <http://www.gnu.org/licenses/>.
 */

#include "ESPEasyAuth.h"

#include "Arduino.h"

Identity IdentityProvider::UNKNOWN(UNKNOWN_ID);
Identity IdentityProvider::ANONYMOUS(ANONYMOUS_ID);
Identity IdentityProvider::AUTHENTICATED(AUTHENTICATED_ID);

Identity* IdentityProvider::CreateIdentity(String const& id) {
	if (!id || id[1] == ID_EXCLUSION || id[1] == ID_ALLIDENTS) {
		ESPEA_LOG("WARNING: Cannot create identity with invalid ID '%s'\n", id.c_str());
		return nullptr;
	}
	return new Identity(id);
}

LinkedList<Identity*> IdentityProvider::parseIdentities(char const *Str) const {
	LinkedList<Identity*> Ret(nullptr);
	while (Str && *Str) {
		String StrIdent = getQuotedToken(Str,',');
		if (!StrIdent) continue;
		if ((StrIdent.length() == 1) && (StrIdent[0] == ID_ALLIDENTS)) {
			_populateIdentities(Ret);
			continue;
		}
		bool Remove = (StrIdent[0] == ID_EXCLUSION);
		if (Remove) StrIdent.remove(0);
		Identity &Ident = getIdentity(StrIdent);
		if (Ident == UNKNOWN) {
			ESPEA_DEBUG("WARNING: Un-recognized identity '%s'!\n", StrIdent.c_str());
			continue;
		}
		if (Remove) {
			if (!Ret.remove_if([&](Identity *const &r){ return *r == Ident; })) {
				ESPEA_DEBUG("WARNING: Ignore missing identity '%s'!\n", StrIdent.c_str());
			}
		} else {
			if (Ret.get_if([&](Identity *const &r){ return *r == Ident; })) {
				ESPEA_DEBUG("WARNING: Ignore duplicate identity '%s'!\n", StrIdent.c_str());
				continue;
			}
			Ret.append(&Ident);
		}
	}
	return Ret;
}

String IdentityProvider::mapIdentities(LinkedList<Identity*> const &idents) const {
	String Ret;
	idents.get_if([&](Identity* const& Ident) {
		putQuotedToken(Ident->ID, Ret, ',');
		return false;
	});
	return Ret;
}

// Basic Account Authority

size_t BasicAccountAuthority::_addAccount(String const &identName, String &&secret) {
	if ((identName == FC(UNKNOWN_ID)) || (identName == FC(ANONYMOUS_ID)) ||
		(identName == FC(AUTHENTICATED_ID))) {
		ESPEA_LOG("WARNING: Cannot update reserved identity '%s'\n", identName.c_str());
		return Accounts.length();
	}
	auto Account = Accounts.get_if([&](SimpleAccountStorage const &x) {
		return x.IDENT->ID == identName;
	});
	if (!secret) {
		if (_WildEmptySecret) {
			ESPEA_LOG("WARNING: Account '%s' will authenticate with any secret!\n",
				identName.c_str());
		} else {
			ESPEA_LOG("WARNING: Account '%s' will NOT authenticates with any secret!\n",
				identName.c_str());
		}
	}
	if (Account) {
		ESPEA_DEBUG("Updating account [%s], new secret: %s\n",
			identName.c_str(), secret.c_str());
		Account->SECRET = std::move(secret);
		return Accounts.length();
	} else {
		auto IDENT = CreateIdentity(identName);
		if (IDENT) {
			ESPEA_DEBUGVV("New account [%s], secret: %s\n",
				identName.c_str(), secret.c_str());
			return Accounts.append({IDENT,std::move(secret)});
		} else return Accounts.length();
	}
}

size_t BasicAccountAuthority::_populateIdentities(LinkedList<Identity*> &list) const {
	size_t Ret = 0;
	for (auto Iter = Accounts.begin(); Iter != Accounts.end(); ++Iter) {
		if (list.get_if([&](Identity *const &r){ return *r == *Iter->IDENT; })) {
			ESPEA_DEBUG("WARNING: Ignore duplicate identity '%s'!\n", Iter->IDENT->ID.c_str());
			continue;
		}
		list.append(Iter->IDENT);
		Ret++;
	}
	return Ret;
}

bool BasicAccountAuthority::removeAccount(char const *identName) {
	return Accounts.remove_if([&](SimpleAccountStorage const &x) {
		return x.IDENT->ID == identName;
	});
}

size_t BasicAccountAuthority::loadAccounts(Stream &source) {
	size_t Count = 0;
	while (source.available()) {
		String Line = source.readStringUntil('\n');
		Line.trim();
		if (!Line) continue;

		char const* Ptr = Line.begin();
		String name = getQuotedToken(Ptr, ':');
		_addAccount(name, Ptr);
		Count++;
	}
	return Count;
}

size_t BasicAccountAuthority::saveAccounts(Print &dest) {
	size_t Count = 0;
	String outLine;
	for (auto Iter = Accounts.begin(); Iter != Accounts.end(); ++Iter) {
		outLine.clear();
		putQuotedToken(Iter->IDENT->ID, outLine, ':');
		outLine.concat(':');
		outLine.concat(Iter->SECRET);
		dest.println(outLine);
		Count++;
	}
	return Count;
}

Identity& BasicAccountAuthority::getIdentity(String const& identName) const {
	if (_AnonymousIdent && identName.equalsIgnoreCase(FC(ANONYMOUS_ID)))
		return ANONYMOUS;
	if (identName.equalsIgnoreCase(FC(AUTHENTICATED_ID)))
		return AUTHENTICATED;
	auto Account = Accounts.get_if([&](SimpleAccountStorage const &x) {
		return x.IDENT->ID.equalsIgnoreCase(identName);
	});
	return Account? *Account->IDENT : UNKNOWN;
}

bool BasicAccountAuthority::Authenticate(Credential &cred,
	AuthSecretCallback const &secret_callback) {
	if (_AnonymousIdent && (cred.IDENT == ANONYMOUS))
		return true;
	auto Account = Accounts.get_if([&](SimpleAccountStorage const &x) {
		return *x.IDENT == cred.IDENT;
	});
	bool Ret = false;
	if (Account) {
		if (Account->SECRET) {
			Ret = _doAuthenticate(*Account, cred, secret_callback);
			cred.disposeSecret();
		} else Ret = _WildEmptySecret;
	}
	return Ret;
}

// Simple Account Authority

PGM_P StrSecretKind(SecretKind kind) {
	switch (kind) {
		case EA_SECRET_NONE: return PSTR_C("None");
		case EA_SECRET_PLAINTEXT: return PSTR_C("Plain-text");
		case EA_SECRET_HTTPDIGESTAUTH_MD5: return PSTR_C("HTTPDigestAuth-MD5");
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: return PSTR_C("HTTPDigestAuth-MD5SESS");
		case EA_SECRET_HTTPDIGESTAUTH_SHA256: return PSTR_C("HTTPDigestAuth-SHA256");
		case EA_SECRET_HTTPDIGESTAUTH_SHA256SESS: return PSTR_C("HTTPDigestAuth-SHA256SESS");
		default: return PSTR_C("???");
	}
}

bool Validate_HTTPDigestPassword(String const &HashedPassword, DigestType dtype,
	Credential &cred, AuthSecretCallback const &secret_callback = nullptr);

bool Validate_ClearPassword(String const &password, Credential &cred,
	AuthSecretCallback const &secret_callback) {
	switch (cred.SECKIND) {
		case EA_SECRET_NONE:
			return false;

		case EA_SECRET_PLAINTEXT:
			return password == cred.SECRET;

		case EA_SECRET_HTTPDIGESTAUTH_MD5:
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: {
			String HA1;
			if (secret_callback) secret_callback(HA1);
			if (HA1) {
				return Validate_HTTPDigestPassword(HA1, EA_DIGEST_MD5_HA1, cred);
			}

			char const* ptr = cred.SECRET.begin();
			String response = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Response: %s\n", response.c_str());
			String realm = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Realm: %s\n", realm.c_str());

			HA1.concat('?',MD5_TXTLEN);
			{
				String HashStr;
				HashStr.concat(cred.IDENT.ID);
				HashStr.concat(':');
				HashStr.concat(realm);
				HashStr.concat(':');
				HashStr.concat(password);
				ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
				textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1.begin());
			}
			// Save session HA1 for future reuse
			if (secret_callback) secret_callback(HA1);
			return Validate_HTTPDigestPassword(HA1, EA_DIGEST_MD5, cred, secret_callback);
		}

		case EA_SECRET_HTTPDIGESTAUTH_SHA256:
		case EA_SECRET_HTTPDIGESTAUTH_SHA256SESS: {
			// Not yet implemented
#if 0
			String HA1;
			if (secret_callback) secret_callback(HA1);
			if (HA1) {
				return Validate_HTTPDigestPassword(HA1, EA_DIGEST_SHA256_HA1, cred);
			}

			char const* ptr = cred.SECRET.begin();
			String response = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Response: %s\n", response.c_str());
			String realm = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Realm: %s\n", realm.c_str());

			String HA1('?',SHA256_TXTLEN);
			{
				String HashStr;
				HashStr.concat(cred.IDENT.ID);
				HashStr.concat(':');
				HashStr.concat(realm);
				HashStr.concat(':');
				HashStr.concat(password);
				ESPEA_DEBUGVV("> SHA256(%s)\n", HashStr.c_str());
				textSHA256_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1.begin());
			}
			// Save session HA1 for future reuse
			if (secret_callback) secret_callback(HA1);
			return Validate_HTTPDigestPassword(HA1, EA_DIGEST_SHA256, cred, secret_callback);
#endif
		}

		default:
			ESPEA_LOG("WARNING: Un-recognized secret kind (%d)\n", cred.SECKIND);
	}
	return false;
}

size_t SimpleAccountAuthority::addAccount(char const *identName, char const *password) {
	return _addAccount(identName, password);
}

bool SimpleAccountAuthority::_doAuthenticate(SimpleAccountStorage const &account,
	Credential &cred, AuthSecretCallback const &secret_callback) {
	return Validate_ClearPassword(account.SECRET, cred, secret_callback);
}

// HTTPDigest Account Authority

PGM_P StrDigestType(DigestType type) {
	switch (type) {
		case EA_DIGEST_MD5: return PSTR_C("MD5");
		case EA_DIGEST_MD5_HA1: return PSTR_C("MD5-HA1");
		case EA_DIGEST_SHA256: return PSTR_C("SHA256");
		case EA_DIGEST_SHA256_HA1: return PSTR_C("SHA256-HA1");
		default: return PSTR_C("???");
	}
}

bool Validate_HTTPDigestPassword(String const &HashedPassword, DigestType dtype,
	Credential &cred, AuthSecretCallback const &secret_callback) {
	switch (cred.SECKIND) {
		case EA_SECRET_NONE:
			return false;

		case EA_SECRET_PLAINTEXT:
			ESPEA_LOG("WARNING: Unsupported secret kind (%d)\n", cred.SECKIND);
			return false;

		case EA_SECRET_HTTPDIGESTAUTH_MD5:
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: {
			SecretKind SECKIND = cred.SECKIND;
			if (dtype != EA_DIGEST_MD5 && dtype != EA_DIGEST_MD5_HA1) {
				ESPEA_LOG("WARNING: Unmatched digest type '%s' (expect '%s' or '%d')\n",
					SFPSTR(StrDigestType(dtype)), SFPSTR(StrDigestType(EA_DIGEST_MD5)),
					SFPSTR(StrDigestType(EA_DIGEST_MD5_HA1)));
				return false;
			}
			if (HashedPassword.length() != MD5_TXTLEN) {
				ESPEA_DEBUG("WARNING: Unexpected digest text length %"PRIi16" (expect %"PRIi16")\n",
					HashedPassword.length(), (unsigned int)MD5_TXTLEN);
				return false;
			}
			char const* ptr = cred.SECRET.begin();
			String response = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Response: %s\n", response.c_str());
			String realm = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Realm: %s\n", realm.c_str());
			String nonce = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Nonce: %s\n", nonce.c_str());
			String qop = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* QoP: %s\n", qop.c_str());
			String cnonce = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* CNonce: %s\n", cnonce.c_str());
			String nc = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* NonceCount: %s\n", nc.c_str());
			String method = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Method: %s\n", method.c_str());
			String uri = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* URI: %s\n", uri.c_str());

			// Validate input
			if (response.length() != MD5_TXTLEN) {
				ESPEA_DEBUG("WARNING: Unexpected response length %"PRIi16" (expect %"PRIi16")\n",
					response.length(), (unsigned int)MD5_TXTLEN);
				return false;
			}
			while (qop) {
				if (qop != "auth") {
					ESPEA_LOG("WARNING: Unsupported QoP '%s'\n", qop.c_str());
				} else if (!nc || !cnonce) {
					ESPEA_DEBUG("WARNING: Missing required secret fields\n");
				} else break;
				return false;
			}
#ifdef STRICT_PROTOCOL
			if (!qop && (nc || (SECKIND != EA_SECRET_HTTPDIGESTAUTH_MD5SESS && cnonce))) {
				ESPEA_DEBUG("WARNING: Excessive secret fields with no QoP\n");
			}
#endif
			String RESP('?',MD5_TXTLEN);
			{
				String HashStr;
				{
					String HA1 = HashedPassword;
					if (dtype == EA_DIGEST_MD5) {
						if (SECKIND == EA_SECRET_HTTPDIGESTAUTH_MD5SESS) {
							HashStr.concat(HashedPassword);
							HashStr.concat(':');
							HashStr.concat(nonce);
							HashStr.concat(':');
							HashStr.concat(cnonce);
							ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
							textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1.begin());
							HashStr.clear();
							// Save session HA1 for future reuse
							if (secret_callback) secret_callback(HA1);
						}
					}
					ESPEA_DEBUGVV("> HA1: %s\n", HA1.c_str());

					{
						String HA2('?', MD5_TXTLEN);
						HashStr.concat(method);
						HashStr.concat(':');
						HashStr.concat(uri);
						ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
						textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA2.begin());
						HashStr.clear();
						ESPEA_DEBUGVV("> HA2: %s\n", HA2.c_str());

						HashStr.concat(HA1);
						HashStr.concat(':');
						HashStr.concat(nonce);
						HashStr.concat(':');
						if (qop == FC("auth")) {
							HashStr.concat(nc);
							HashStr.concat(':');
							HashStr.concat(cnonce);
							HashStr.concat(':');
							HashStr.concat(qop);
							HashStr.concat(':');
						}
						HashStr.concat(HA2);
					}
					ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
					textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP.begin());
					ESPEA_DEBUGVV("> RESP: %s\n", RESP.c_str());
				}
			}

			return response == RESP;
		}

		case EA_SECRET_HTTPDIGESTAUTH_SHA256:
		case EA_SECRET_HTTPDIGESTAUTH_SHA256SESS: {
			// Not yet implemented
#if 0
			SecretKind SECKIND = cred.SECKIND;
			if (dtype != EA_DIGEST_SHA256 && dtype != EA_DIGEST_SHA256_HA1) {
				ESPEA_LOG("WARNING: Unmatched digest type '%s' (expect '%s' or '%s')\n",
					SFPSTR(StrDigestType(dtype)), SFPSTR(StrDigestType(EA_DIGEST_SHA256)),
						SFPSTR(StrDigestType(EA_DIGEST_SHA256_HA1)));
				return false;
			}
			if (HashedPassword.length() != SHA256_TXTLEN) {
				ESPEA_DEBUG("WARNING: Unexpected digest text length %"PRIi16" (expect %"PRIi16")\n",
				HashedPassword.length(), (unsigned int)SHA256_TXTLEN);
				return false;
			}
			char const* ptr = cred.SECRET.begin();
			String response = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Response: %s\n", response.c_str());
			String realm = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Realm: %s\n", realm.c_str());
			String nonce = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Nonce: %s\n", nonce.c_str());
			String qop = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* QoP: %s\n", qop.c_str());
			String cnonce = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* CNonce: %s\n", cnonce.c_str());
			String nc = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* NonceCount: %s\n", nc.c_str());
			String method = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Method: %s\n", method.c_str());
			String uri = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* URI: %s\n", uri.c_str());

			// Validate input
			if (response.length() != SHA256_TXTLEN) {
				ESPEA_DEBUG("WARNING: Unexpected response length %"PRIi16" (expect %"PRIi16")\n",
					response.length(), (unsigned int)SHA256_TXTLEN);
				return false;
			}
			while (qop) {
				if (qop != "auth") {
					ESPEA_LOG("WARNING: Unsupported QoP '%s'\n", qop.c_str());
				} else if (!nc || !cnonce) {
					ESPEA_DEBUG("WARNING: Missing required secret fields\n");
				} else break;
				return false;
			}
#ifdef STRICT_PROTOCOL
				if (!qop && (nc || (SECKIND != EA_SECRET_HTTPDIGESTAUTH_SHA256SESS && cnonce))) {
					ESPEA_DEBUG("WARNING: Excessive secret fields with no QoP\n");
				}
#endif
			String RESP('?',SHA256_TXTLEN);
			{
				String HashStr;
				{
					String HA1 = HashedPassword;
					if (dtype == EA_DIGEST_SHA256) {
						if (SECKIND == EA_SECRET_HTTPDIGESTAUTH_SHA256SESS) {
							HashStr.concat(HashedPassword);
							HashStr.concat(':');
							HashStr.concat(nonce);
							HashStr.concat(':');
							HashStr.concat(cnonce);
							ESPEA_DEBUGVV("> SHA256(%s)\n", HashStr.c_str());
							textSHA256_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1.begin());
							HashStr.clear();
							// Save session HA1 for future
							if (secret_callback) secret_callback(HA1);
						}
					}
					ESPEA_DEBUGVV("> HA1: %s\n", HA1.c_str());

					{
						String HA2('?',SHA256_TXTLEN);
						HashStr.concat(method);
						HashStr.concat(':');
						HashStr.concat(uri);
						ESPEA_DEBUGVV("> SHA256(%s)\n", HashStr.c_str());
						textSHA256_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA2.begin());
						HashStr.clear();
						ESPEA_DEBUGVV("> HA2: %s\n", HA2.c_str());

						HashStr.concat(HA1);
						HashStr.concat(':');
						HashStr.concat(nonce);
						HashStr.concat(':');
						if (qop == FC("auth")) {
							HashStr.concat(nc);
							HashStr.concat(':');
							HashStr.concat(cnonce);
							HashStr.concat(':');
							HashStr.concat(qop);
							HashStr.concat(':');
						}
						HashStr.concat(HA2);
					}
					ESPEA_DEBUGVV("> SHA256(%s)\n", HashStr.c_str());
					textSHA256_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP.begin());
				}
				ESPEA_DEBUGVV("> RESP: %s\n",RESP.c_str());
			}

			return response == RESP;
#endif
		}

		default:
			ESPEA_LOG("WARNING: Un-recognized secret kind (%d)\n", cred.SECKIND);
	}
	return false;
}

size_t HTTPDigestAccountAuthority::addAccount(char const *identName, char const *password) {
	String HA1Password;
	if (password && *password) {
		switch (_DType) {
			case EA_DIGEST_MD5: {
				HA1Password.concat('?',MD5_TXTLEN);
				String HashStr;
				HashStr.concat(identName);
				HashStr.concat(':');
				HashStr.concat(Realm);
				HashStr.concat(':');
				HashStr.concat(password);
				ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
				textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1Password.begin());
			} break;
			case EA_DIGEST_SHA256: {
#if 0
				HA1Password.concat('?',SHA256_TXTLEN);
				String HashStr;
				HashStr.concat(identName);
				HashStr.concat(':');
				HashStr.concat(Realm);
				HashStr.concat(':');
				HashStr.concat(password);
				ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
				textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1Password.begin());
#endif
			} break;
			default: {
				ESPEA_LOG("WARNING: Un-recognized digest type (%d)\n", _DType);
				return Accounts.length();
			}
		}
	}
	return BasicAccountAuthority::_addAccount(identName, std::move(HA1Password));
}

size_t HTTPDigestAccountAuthority::_addAccount(String const &identName, String &&secret) {
	switch (_DType) {
		case EA_DIGEST_MD5: {
			if (secret.length() != MD5_TXTLEN) {
				ESPEA_LOG("WARNING: Unexpected secret length %"PRIi16" (expect %"PRIi16")\n",
					secret.length(), (unsigned int)MD5_TXTLEN);
				return Accounts.length();
			}
		} break;
		case EA_DIGEST_SHA256: {
#if 0
			if (secret.length() != SHA256_TXTLEN) {
				ESPEA_LOG("WARNING: Unexpected secret length %"PRIi16" (expect %"PRIi16")\n",
					secret.length(), (unsigned int)SHA256_TXTLEN);
				return Accounts.length();
			}
#endif
		} break;
		default: {
			ESPEA_LOG("WARNING: Un-recognized digest type (%d)\n", _DType);
			return Accounts.length();
		}
	}
	return BasicAccountAuthority::_addAccount(identName, std::move(secret));
}

bool HTTPDigestAccountAuthority::_doAuthenticate(SimpleAccountStorage const &account,
	Credential &cred, AuthSecretCallback const &secret_callback) {
	String HA1;
	if (secret_callback) secret_callback(HA1);
	if (HA1) {
		switch (_DType) {
			case EA_DIGEST_MD5:
				return Validate_HTTPDigestPassword(HA1, EA_DIGEST_MD5_HA1, cred);
			case EA_DIGEST_SHA256:
				return Validate_HTTPDigestPassword(HA1, EA_DIGEST_SHA256_HA1, cred);
			default: {
				ESPEA_LOG("WARNING: Un-recognized digest type (%d)\n", _DType);
			}
		}
	}
	return Validate_HTTPDigestPassword(account.SECRET, _DType, cred, secret_callback);
}
