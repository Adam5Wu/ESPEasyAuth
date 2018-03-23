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

#ifndef ESPEasyAuth_H
#define ESPEasyAuth_H

#include <Misc.h>

#ifndef ESPEA_DEBUG_LEVEL
#define ESPEA_DEBUG_LEVEL ESPZW_DEBUG_LEVEL
#endif

#ifndef ESPEA_LOG
#define ESPEA_LOG(...) ESPZW_LOG(__VA_ARGS__)
#endif

#if ESPEA_DEBUG_LEVEL < 1
	#define ESPEA_DEBUGDO(...)
	#define ESPEA_DEBUG(...)
#else
	#define ESPEA_DEBUGDO(...) __VA_ARGS__
	#define ESPEA_DEBUG(...) ESPEA_LOG(__VA_ARGS__)
#endif

#if ESPEA_DEBUG_LEVEL < 2
	#define ESPEA_DEBUGVDO(...)
	#define ESPEA_DEBUGV(...)
#else
	#define ESPEA_DEBUGVDO(...) __VA_ARGS__
	#define ESPEA_DEBUGV(...) ESPEA_LOG(__VA_ARGS__)
#endif

#if ESPEA_DEBUG_LEVEL < 3
	#define ESPEA_DEBUGVVDO(...)
	#define ESPEA_DEBUGVV(...)
#else
	#define ESPEA_DEBUGVVDO(...) __VA_ARGS__
	#define ESPEA_DEBUGVV(...) ESPEA_LOG(__VA_ARGS__)
#endif

//#define SECURE_SECRET_WIPE
#define STRICT_PROTOCOL

#include <utility>
#include <functional>
#include "WString.h"
#include "LinkedList.h"
#include "StringArray.h"

#define UNKNOWN_ID			"<Unknown>"
#define ANONYMOUS_ID		"<Anonymous>"
#define AUTHENTICATED_ID	"<Authenticated>"
#define ID_ALLIDENTS		'*'
#define ID_EXCLUSION		'-'

class IdentityProvider;

// Instance only comes from IdentityProvider, and is globally unique
class Identity {
	friend class IdentityProvider;

	protected:
		Identity(String const &id) : ID(id) {}
		Identity(String &&id) : ID(std::move(id)) {}

		Identity(Identity const&) = delete;
		Identity &operator=(Identity const&) = delete;

	public:
		String const ID;

		String toString(void) const { return ID; }
};

inline bool operator==(const Identity &lhs, const Identity &rhs)
{ return &lhs == &rhs; }

inline bool operator!=(const Identity &lhs, const Identity &rhs)
{ return &lhs != &rhs; }

typedef enum {
	EA_SECRET_NONE,
	EA_SECRET_PLAINTEXT,
	EA_SECRET_HTTPDIGESTAUTH_MD5,
	EA_SECRET_HTTPDIGESTAUTH_MD5SESS,
	EA_SECRET_HTTPDIGESTAUTH_SHA256,
	EA_SECRET_HTTPDIGESTAUTH_SHA256SESS,
} SecretKind;

struct Credential {
	Identity &IDENT;
	SecretKind SECKIND;
	String SECRET;

	Credential(Identity &ident) : IDENT(ident), SECKIND(EA_SECRET_NONE) {}
	Credential(Identity &ident, SecretKind seckind, String &&secret)
	: IDENT(ident), SECKIND(seckind), SECRET(std::move(secret)) {}

	void setSecret(SecretKind seckind, String &&secret) {
		disposeSecret();
		SECKIND = seckind;
		SECRET = std::move(secret);
	}

	void disposeSecret(void) {
		if (SECKIND != EA_SECRET_NONE) {
			SECKIND = EA_SECRET_NONE;
#ifdef SECURE_SECRET_WIPE
			memset(SECRET.begin(), SECRET.length(), 0);
#endif
			SECRET.clear(true);
		}
	}
};

typedef std::function<void(String &)> AuthSecretCallback;

class Authorizer {
	public:
		virtual ~Authorizer(void) {}
		virtual bool Authenticate(Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) = 0;
		virtual bool Authorize(Identity &ident, Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) = 0;
};

class BasicAuthorizer : public Authorizer {
	public:
		virtual bool Authorize(Identity &ident, Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) override {
			if (cred.IDENT == ident) {
				return Authenticate(cred, secret_callback);
			}
			return cred.disposeSecret(), false;
		}
};

class DummyAuthorizer : public BasicAuthorizer {
	public:
		bool const AuthState;

		DummyAuthorizer(bool state = false) : AuthState(state) {}

		virtual bool Authenticate(Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) override {
			return cred.disposeSecret(), AuthState;
		}
};

class AuthSession {
	protected:
		Authorizer *AUTH;

	public:
		Identity &IDENT;

		AuthSession(Identity &ident, Authorizer *auth)
		: AUTH(auth), IDENT(ident) {}

		AuthSession(AuthSession &&session)
		: AUTH(session.AUTH), IDENT(session.IDENT) {}

		virtual ~AuthSession(void) {}

		bool isAuthorized(void) const { return !AUTH; }

		bool Authorize(SecretKind skind, char const *secret,
			AuthSecretCallback const &secret_callback = nullptr) {
			return Authorize(skind, String(secret), secret_callback);
		}
		bool Authorize(SecretKind skind, String &&secret,
			AuthSecretCallback const &secret_callback = nullptr) {
			Credential C(IDENT, skind, std::move(secret));
			return Authorize(C, secret_callback);
		}
		bool Authorize(Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) {
			if (AUTH && AUTH->Authorize(IDENT, cred, secret_callback)) {
				AUTH = nullptr;
			}
			return isAuthorized();
		}

		String toString(void) const {
			String Ret;
			Ret.concat('{');
			Ret.concat(IDENT.toString());
			Ret.concat('(');
			Ret.concat(isAuthorized()?FL("Authorized"):FL("Unauthorized"));
			Ret.concat(")}",2);
			return Ret;
		}
};

class IdentityProvider {
	protected:
		Identity* CreateIdentity(String const &id);
		virtual size_t _populateIdentities(LinkedList<Identity*> &list) const = 0;
	public:
		virtual ~IdentityProvider(void) {}

		static Identity UNKNOWN;
		static Identity ANONYMOUS;
		static Identity AUTHENTICATED;
		virtual Identity &getIdentity(String const &identName) const = 0;

		LinkedList<Identity*> parseIdentities(char const *Str) const;
		String mapIdentities(LinkedList<Identity*> const &idents) const;
};

class DummyIdentityProvider : public IdentityProvider {
	protected:
		virtual size_t _populateIdentities(LinkedList<Identity*> &list) const override
		{ return 0; }
	public:
		virtual Identity &getIdentity(String const &identName) const override
		{ return UNKNOWN; }
};

class SessionAuthority {
	public:
		IdentityProvider * const IDP;
		Authorizer * const AUTH;

		SessionAuthority(IdentityProvider *idp, Authorizer *auth)
		: IDP(idp), AUTH(auth) {}

		virtual ~SessionAuthority(void) {}

		AuthSession getSession(String const &identName)
		{ return getSession(IDP->getIdentity(identName)); }

		AuthSession getSession(Identity &ident)
		{ return AuthSession(ident, AUTH); }

		AuthSession getSession(char const* identName, SecretKind skind,
			char const* secret, AuthSecretCallback const &secret_callback = nullptr)
		{ return getSession(identName, skind, String(secret), secret_callback); }

		AuthSession getSession(String const &identName, SecretKind skind,
			String &&secret, AuthSecretCallback const &secret_callback = nullptr) {
			Credential cred(IDP->getIdentity(identName), skind, std::move(secret));
			return getSession(cred, secret_callback);
		}

		AuthSession getSession(Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) {
			AuthSession session(cred.IDENT, AUTH);
			session.Authorize(cred, secret_callback);
			return std::move(session);
		}
};

class DummySessionAuthority : public SessionAuthority {
	protected:
		DummyIdentityProvider D_IDP;
		DummyAuthorizer D_AUTH;

	public:
		DummySessionAuthority(bool authState = false)
		: SessionAuthority(&D_IDP, &D_AUTH), D_AUTH(authState) {}
};

class BasicAccountAuthority : public IdentityProvider, public BasicAuthorizer {
	protected:
		bool _AnonymousIdent;
		bool _WildEmptySecret;
		struct SimpleAccountStorage {
			Identity* IDENT;
			String SECRET;
		};
		LinkedList<SimpleAccountStorage> Accounts;

		virtual size_t _addAccount(String const &identName, String &&secret);
		virtual bool _doAuthenticate(SimpleAccountStorage const &account,
			Credential &cred, AuthSecretCallback const &secret_callback) = 0;
		virtual size_t _populateIdentities(LinkedList<Identity*> &list) const override;

	public:
		BasicAccountAuthority(bool AnonymousIdent, bool WildEmptySecret)
		: _AnonymousIdent(AnonymousIdent), _WildEmptySecret(WildEmptySecret),
			Accounts([](SimpleAccountStorage &x){delete x.IDENT;}) {}

		bool removeAccount(char const *identName);

		size_t loadAccounts(Stream &source);
		size_t saveAccounts(Print &dest);

		virtual Identity &getIdentity(String const &identName) const override;
		virtual bool Authenticate(Credential &cred,
			AuthSecretCallback const &secret_callback = nullptr) override;
};

class SimpleAccountAuthority : public BasicAccountAuthority {
	protected:
		virtual bool _doAuthenticate(SimpleAccountStorage const &account,
			Credential &cred, AuthSecretCallback const &secret_callback) override;

	public:
		SimpleAccountAuthority(bool AnonymousIdent = true, bool AllowNoPassword = true)
		: BasicAccountAuthority(AnonymousIdent, AllowNoPassword) {}
		~SimpleAccountAuthority(void) {}

		size_t addAccount(char const *identName, char const *password)
		{ return addAccount(String(identName), String(password)); }
		size_t addAccount(String const &identName, String && password)
		{ return _addAccount(identName, std::move(password)); }
};

typedef enum {
	EA_DIGEST_MD5,
	EA_DIGEST_MD5_HA1,
	EA_DIGEST_SHA256,
	EA_DIGEST_SHA256_HA1,
} DigestType;

class HTTPDigestAccountAuthority : public BasicAccountAuthority {
	protected:
		DigestType const _DType;
		virtual size_t _addAccount(String const &identName, String &&secret) override;
		virtual bool _doAuthenticate(SimpleAccountStorage const &account,
			Credential &cred, AuthSecretCallback const &secret_callback) override;

	public:
		String const Realm;
		HTTPDigestAccountAuthority(String const &realm, DigestType dtype = EA_DIGEST_MD5,
			bool AnonymousIdent = true, bool AllowNoPassword = true)
		: BasicAccountAuthority(AnonymousIdent, AllowNoPassword), Realm(realm), _DType(dtype) {}

		size_t addAccount(char const *identName, char const *password)
		{ return addAccount(String(identName), String(password)); }
		size_t addAccount(String const &identName, String && password);
};

#endif // ESPEasyAuth_H
