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

Identity IdentityProvider::UNKNOWN_IDENTITY("<Unknown-Identity>");
Identity IdentityProvider::ANONYMOUS("Anonymous");

LinkedList<Identity*> IdentityProvider::parseIdentities(char const *Str) const {
	LinkedList<Identity*> Ret(NULL);
	while (Str && *Str) {
		String StrIdent = getQuotedToken(Str,',');
		if (StrIdent.empty()) continue;
		Identity &Ident = getIdentity(StrIdent);
		if (Ident == UNKNOWN_IDENTITY) {
			ESPEA_DEBUG("WARNING: Unrecognised identity '%s'!\n", StrIdent.c_str());
			continue;
		}
		if (Ret.get_if([&](Identity *const &r){ return *r == Ident; })) {
			ESPEA_DEBUG("WARNING: Ignore duplicate identity '%s'!\n", StrIdent.c_str());
			continue;
		}
		Ret.append(&Ident);
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

bool Validate_ClearPassword(String const& password, Credential& cred);

size_t SimpleAccountAuthority::addAccount(char const *identName, char const *password) {
	if (UNKNOWN_IDENTITY.ID.equals(identName)) {
		ESPEA_DEBUG("WARNING: Cannot update reserved identity '%s'\n", identName);
		return Accounts.length();
	}
	SimpleAccount* Account = Accounts.get_if([&](SimpleAccount const &x) {
		return x.IDENT->ID.equals(identName);
	});
	if (!password || !*password) {
		if (_AllowNoPassword) ESPEA_DEBUG("WARNING: Account '%s' will authenticate with any password!\n", identName);
		else ESPEA_DEBUG("WARNING: Account '%s' will NOT authenticates with any password!\n", identName);
	}
	if (Account) {
		ESPEA_DEBUG("WARNING: Updating password of existing account '%s'\n", identName);
		Account->Password = password;
		return Accounts.length();
	} else {
		ESPEA_DEBUGVV("Account [%s], password: %s\n", identName, password);
		return Accounts.append({CreateIdentity(identName),password});
	}
}

bool SimpleAccountAuthority::removeAccount(char const *identName) {
	return Accounts.remove_if([&](SimpleAccount const &x) {
		return x.IDENT->ID.equals(identName);
	});
}

size_t SimpleAccountAuthority::loadAccounts(Stream &source) {
	size_t Count = 0;
	while (source.available()) {
		String Line = source.readStringUntil('\n');
		Line.trim();
		if (Line.empty()) continue;

		char const* Ptr = Line.begin();
		String name = getQuotedToken(Ptr, ':');
		addAccount(name.begin(), Ptr);
		Count++;
	}
	return Count;
}

Identity& SimpleAccountAuthority::getIdentity(String const& identName) const {
	SimpleAccount* Account = Accounts.get_if([&](SimpleAccount const &x) {
		return x.IDENT->ID.equalsIgnoreCase(identName);
	});
	return Account? *Account->IDENT : UNKNOWN_IDENTITY;
}

bool SimpleAccountAuthority::Authenticate(Credential& cred) {
	SimpleAccount* Account = Accounts.get_if([&](SimpleAccount const &x) {
		return *x.IDENT == cred.IDENT;
	});
	bool Ret = false;
	if (Account) {
		if (Account->Password.empty()) Ret = _AllowNoPassword;
		else Ret = Validate_ClearPassword(Account->Password, cred);
		cred.disposeSecret();
	}
	return Ret;
}

char const* StrSecretKind(SecretKind kind) {
	switch (kind) {
		case EA_SECRET_NONE: return "None";
		case EA_SECRET_PLAINTEXT: return "Plain-text";
		case EA_SECRET_HTTPDIGESTAUTH_MD5: return "HTTPDigestAuth-MD5";
		case EA_SECRET_HTTPDIGESTAUTH_MD5SESS: return "HTTPDigestAuth-MD5SESS";
		default: return "???";
	}
}

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
			if (response.length() != 32) {
				ESPEA_DEBUG("WARNING: Unexpected response length %d\n", response.length());
				return false;
			}
			while (!qop.empty()) {
				if (!qop.equals("auth")) {
					ESPEA_DEBUG("WARNING: Unsupported QoP '%s'\n", qop.c_str());
				} else if (nc.empty() || cnonce.empty()) {
					ESPEA_DEBUG("WARNING: Missing required secret fields\n");
				} else break;
				return false;
			}
#ifdef STRICT_PROTOCOL
			if (qop.empty() && (!nc.empty() || (cred.SECKIND != EA_SECRET_HTTPDIGESTAUTH_MD5SESS && !cnonce.empty()))) {
				ESPEA_DEBUG("WARNING: Excessive secret fields with no QoP\n");
			}
#endif

			char HA1[32];
			String HashStr;
			HashStr.concat(cred.IDENT.ID);
			HashStr.concat(':');
			HashStr.concat(realm);
			HashStr.concat(':');
			HashStr.concat(password);
			ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
			textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
			HashStr.clear();
			if (cred.SECKIND == EA_SECRET_HTTPDIGESTAUTH_MD5SESS) {
				HashStr.concat(HA1,32);
				HashStr.concat(':');
				HashStr.concat(nonce);
				HashStr.concat(':');
				HashStr.concat(cnonce);
				ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
				textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
				HashStr.clear();
			}
			ESPEA_DEBUGVV("> HA1: %s\n", String(HA1,32).c_str());

			char HA2[32];
			HashStr.concat(method);
			HashStr.concat(':');
			HashStr.concat(uri);
			ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
			textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA2);
			HashStr.clear();
			ESPEA_DEBUGVV("> HA2: %s\n", String(HA2,32).c_str());

			char RESP[32];
			HashStr.concat(HA1,32);
			HashStr.concat(':');
			HashStr.concat(nonce);
			HashStr.concat(':');
			if (qop.equals("auth")) {
				HashStr.concat(nc);
				HashStr.concat(':');
				HashStr.concat(cnonce);
				HashStr.concat(':');
				HashStr.concat(qop);
				HashStr.concat(':');
			} else if (!qop.empty()) {
				ESPEA_DEBUG("WARNING: Unsupported QoP '%s'\n", qop.c_str());
				return false;
			}
			HashStr.concat(HA2,32);
			ESPEA_DEBUGVV("> MD5(%s)\n", HashStr.c_str());
			textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP);
			ESPEA_DEBUGVV("> RESP: %s\n", String(RESP,32).c_str());

			return response.startsWith(RESP,32,0,false);
		}

		default:
			ESPEA_DEBUG("WARNING: Unrecognised secret kind '%s'\n", StrSecretKind(cred.SECKIND));
	}
	return false;
}
