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

#include "Arduino.h"
#include "ESPEasyAuth.h"
#include "Misc.h"

Identity IdentityProvider::ANONYMOUS(ANONYMOUS_ID);
Identity IdentityProvider::UNKNOWN(UNKNOWN_ID);

Identity* IdentityProvider::CreateIdentity(String const& id) {
	if (!id || id[1] == ID_EXCLUSION) {
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
		if (StrIdent.equals("*")) {
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

size_t BasicAccountAuthority::_addAccount(char const *identName, String &&secret) {
	if (UNKNOWN.ID.equals(identName) || ANONYMOUS.ID.equals(identName)) {
		ESPEA_LOG("WARNING: Cannot update reserved identity '%s'\n", identName);
		return Accounts.length();
	}
	auto Account = Accounts.get_if([&](SimpleAccountStorage const &x) {
		return x.IDENT->ID.equals(identName);
	});
	if (!secret) {
		if (_WildEmptySecret) {
			ESPEA_LOG("WARNING: Account '%s' will authenticate with any secret!\n", identName);
		} else {
			ESPEA_LOG("WARNING: Account '%s' will NOT authenticates with any secret!\n", identName);
		}
	}
	if (Account) {
		ESPEA_DEBUG("Updating account [%s], new secret: %s\n", identName, secret.c_str());
		Account->SECRET = std::move(secret);
		return Accounts.length();
	} else {
		auto IDENT = CreateIdentity(identName);
		if (IDENT) {
			ESPEA_DEBUGVV("New account [%s], secret: %s\n", identName, secret.c_str());
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
		return x.IDENT->ID.equals(identName);
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
		_addAccount(name.begin(), Ptr);
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
	if (_AnonymousIdent && identName.equalsIgnoreCase(ANONYMOUS.ID))
		return ANONYMOUS;
	auto Account = Accounts.get_if([&](SimpleAccountStorage const &x) {
		return x.IDENT->ID.equalsIgnoreCase(identName);
	});
	return Account? *Account->IDENT : UNKNOWN;
}

bool BasicAccountAuthority::Authenticate(Credential& cred) {
	if (_AnonymousIdent && (cred.IDENT == ANONYMOUS))
		return true;
	auto Account = Accounts.get_if([&](SimpleAccountStorage const &x) {
		return *x.IDENT == cred.IDENT;
	});
	bool Ret = false;
	if (Account) {
		if (!Account->SECRET) Ret = _WildEmptySecret;
		else Ret = _doAuthenticate(*Account, cred);
		cred.disposeSecret();
	}
	return Ret;
}

// Simple Account Authority

String StrSecretKind(SecretKind kind) {
	switch (kind) {
		case EA_SECRET_NONE: return "None";
		case EA_SECRET_PLAINTEXT: return "Plain-text";
		case EA_SECRET_HTTPDIGESTAUTH_MD5: return "HTTPDigestAuth-MD5";
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: return "HTTPDigestAuth-MD5SESS";
		case EA_SECRET_HTTPDIGESTAUTH_SHA256: return "HTTPDigestAuth-SHA256";
		case EA_SECRET_HTTPDIGESTAUTH_SHA256SESS: return "HTTPDigestAuth-SHA256SESS";
		default: return "Unknown ("+(int)kind+')';
	}
}

bool Validate_HTTPDigestPassword(String const& HashedPassword, DigestType dtype, Credential& cred);

bool Validate_ClearPassword(String const& password, Credential& cred) {
	switch (cred.SECKIND) {
		case EA_SECRET_NONE:
			return false;

		case EA_SECRET_PLAINTEXT:
			return password.equals(cred.SECRET);

		case EA_SECRET_HTTPDIGESTAUTH_MD5:
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: {
			char const* ptr = cred.SECRET.begin();
			String response = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Response: %s\n", response.c_str());
			String realm = getQuotedToken(ptr);
			ESPEA_DEBUGVV("* Realm: %s\n", realm.c_str());

			String HA1('?',MD5_TXTLEN);
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
			return Validate_HTTPDigestPassword(HA1, EA_DIGEST_MD5, cred);
		}

		case EA_SECRET_HTTPDIGESTAUTH_SHA256:
		case EA_SECRET_HTTPDIGESTAUTH_SHA256SESS: {
			// Not yet implemented
#if 0
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
			return Validate_HTTPDigestPassword(HA1, EA_DIGEST_SHA256, cred);
#endif
		}

		default:
			ESPEA_LOG("WARNING: Un-recognized secret kind '%s'\n", StrSecretKind(cred.SECKIND).c_str());
	}
	return false;
}

size_t SimpleAccountAuthority::addAccount(char const *identName, char const *password) {
	return _addAccount(identName, password);
}

bool SimpleAccountAuthority::_doAuthenticate(SimpleAccountStorage const &account, Credential& cred) {
	return Validate_ClearPassword(account.SECRET, cred);
}

// HTTPDigest Account Authority

String StrDigestType(DigestType type) {
	switch (type) {
		case EA_DIGEST_MD5: return "MD5";
		case EA_DIGEST_SHA256: return "SHA256";
		default: return "Unknown ("+(int)type+')';
	}
}

bool Validate_HTTPDigestPassword(String const& HashedPassword, DigestType dtype, Credential& cred) {
	switch (cred.SECKIND) {
		case EA_SECRET_NONE:
			return false;

		case EA_SECRET_PLAINTEXT:
			ESPEA_LOG("WARNING: Unsupported secret kind '%s'\n", StrSecretKind(cred.SECKIND).c_str());
			return false;

		case EA_SECRET_HTTPDIGESTAUTH_MD5:
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: {
			if (dtype != EA_DIGEST_MD5) {
				ESPEA_LOG("WARNING: Unmatched digest type '%s' (expect '%s')\n",
					StrDigestType(dtype).c_str(), StrDigestType(EA_DIGEST_MD5).c_str());
				return false;
			}
			if (HashedPassword.length() != MD5_TXTLEN) {
				ESPEA_DEBUG("WARNING: Unexpected digest text length %d (expect %d)\n",
					HashedPassword.length(), MD5_TXTLEN);
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
				ESPEA_DEBUG("WARNING: Unexpected response length %d (expect)\n", response.length(), MD5_TXTLEN);
				return false;
			}
			while (qop) {
				if (!qop.equals("auth")) {
					ESPEA_LOG("WARNING: Unsupported QoP '%s'\n", qop.c_str());
				} else if (!nc || !cnonce) {
					ESPEA_DEBUG("WARNING: Missing required secret fields\n");
				} else break;
				return false;
			}
#ifdef STRICT_PROTOCOL
			if (!qop && (nc || (cred.SECKIND != EA_SECRET_HTTPDIGESTAUTH_MD5SESS && cnonce))) {
				ESPEA_DEBUG("WARNING: Excessive secret fields with no QoP\n");
			}
#endif
			String RESP('?',MD5_TXTLEN);
			{
				String HashStr;
				{
					String HA1 = HashedPassword;
					if (cred.SECKIND == EA_SECRET_HTTPDIGESTAUTH_MD5SESS) {
						HashStr.concat(HashedPassword);
						HashStr.concat(':');
						HashStr.concat(nonce);
						HashStr.concat(':');
						HashStr.concat(cnonce);
						ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
						textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1.begin());
						HashStr.clear();
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
						//if (qop.equals("auth")) {
							HashStr.concat(nc);
							HashStr.concat(':');
							HashStr.concat(cnonce);
							HashStr.concat(':');
							HashStr.concat(qop);
							HashStr.concat(':');
						//}
						HashStr.concat(HA2);
					}
					ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
					textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP.begin());
					ESPEA_DEBUGVV("> RESP: %s\n", RESP.c_str());
				}
			}

			return response.equals(RESP);
		}

		case EA_SECRET_HTTPDIGESTAUTH_SHA256:
		case EA_SECRET_HTTPDIGESTAUTH_SHA256SESS: {
			// Not yet implemented
#if 0
			if (dtype != EA_DIGEST_SHA256) {
				ESPEA_LOG("WARNING: Unmatched digest type '%s' (expect '%s')\n",
				StrDigestType(dtype).c_str(), StrDigestType(EA_DIGEST_SHA256).c_str());
				return false;
			}
			if (HashedPassword.length() != SHA256_TXTLEN) {
				ESPEA_DEBUG("WARNING: Unexpected digest text length %d (expect %d)\n",
				HashedPassword.length(), SHA256_TXTLEN);
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
				ESPEA_DEBUG("WARNING: Unexpected response length %d (expect)\n", response.length(), SHA256_TXTLEN);
				return false;
			}
			while (qop) {
				if (!qop.equals("auth")) {
					ESPEA_LOG("WARNING: Unsupported QoP '%s'\n", qop.c_str());
				} else if (!nc || !cnonce) {
					ESPEA_DEBUG("WARNING: Missing required secret fields\n");
				} else break;
				return false;
			}
#ifdef STRICT_PROTOCOL
				if (!qop && (nc || (cred.SECKIND != EA_SECRET_HTTPDIGESTAUTH_SHA256SESS && cnonce))) {
					ESPEA_DEBUG("WARNING: Excessive secret fields with no QoP\n");
				}
#endif
			String RESP('?',SHA256_TXTLEN);
			{
				String HashStr;
				{
					String HA1 = HashedPassword;
					if (cred.SECKIND == EA_SECRET_HTTPDIGESTAUTH_SHA256SESS) {
						HashStr.concat(HashedPassword);
						HashStr.concat(':');
						HashStr.concat(nonce);
						HashStr.concat(':');
						HashStr.concat(cnonce);
						ESPEA_DEBUGVV("> SHA256(%s)\n", HashStr.c_str());
						textSHA256_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1.begin());
						HashStr.clear();
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
						//if (qop.equals("auth")) {
							HashStr.concat(nc);
							HashStr.concat(':');
							HashStr.concat(cnonce);
							HashStr.concat(':');
							HashStr.concat(qop);
							HashStr.concat(':');
						//}
						HashStr.concat(HA2);
					}
					ESPEA_DEBUGVV("> SHA256(%s)\n", HashStr.c_str());
					textSHA256_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP.begin());
				}
				ESPEA_DEBUGVV("> RESP: %s\n",RESP.c_str());
			}

			return response.equals(RESP);
#endif
		}

		default:
			ESPEA_LOG("WARNING: Un-recognized secret kind '%s'\n", StrSecretKind(cred.SECKIND).c_str());
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
				ESPEA_LOG("WARNING: Un-recognized digest type '%s'\n", StrDigestType(_DType).c_str());
				return Accounts.length();
			}
		}
	}
	return BasicAccountAuthority::_addAccount(identName, std::move(HA1Password));
}

size_t HTTPDigestAccountAuthority::_addAccount(char const *identName, String &&secret) {
	switch (_DType) {
		case EA_DIGEST_MD5: {
			if (secret.length() != MD5_TXTLEN) {
				ESPEA_LOG("WARNING: Unexpected secret length %d (expect)\n", secret.length(), MD5_TXTLEN);
				return Accounts.length();
			}
		} break;
		case EA_DIGEST_SHA256: {
#if 0
			if (secret.length() != SHA256_TXTLEN) {
				ESPEA_LOG("WARNING: Unexpected secret length %d (expect)\n", secret.length(), SHA256_TXTLEN);
				return Accounts.length();
			}
#endif
		} break;
		default: {
			ESPEA_LOG("WARNING: Un-recognized digest type '%s'\n", StrDigestType(_DType).c_str());
			return Accounts.length();
		}
	}
	return BasicAccountAuthority::_addAccount(identName, std::move(secret));
}

bool HTTPDigestAccountAuthority::_doAuthenticate(SimpleAccountStorage const &account, Credential& cred) {
	return Validate_HTTPDigestPassword(account.SECRET, _DType, cred);
}
