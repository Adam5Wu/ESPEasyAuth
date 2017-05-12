// This demo requires a modified ESP8266 Arduino, found here:
// https://github.com/Adam5Wu/Arduino

// This demo requires ZWUtils-Arduino library, found here:
// https://github.com/Adam5Wu/ZWUtils-Arduino

#include "Misc.h"
#include "ESPEasyAuth.h"

SimpleAccountAuthority SAX; 
SessionAuthority SA(&SAX, &SAX);

void setup() {
  Serial.begin(115200);
	Serial.println();

	SAX.addAccount("test","Test!");
	SAX.addAccount("test1","Test1");
	SAX.addAccount("test1","Test2");
	if (SAX.removeAccount("test1")) {
		Serial.println("Account 'test1' removed!");
	} else {
		Serial.println("Account 'test1' not exist!");
	}
	if (SAX.removeAccount("test1")) {
		Serial.println("Account 'test1' removed!");
	} else {
		Serial.println("Account 'test1' not exist!");
	}
}

void loop() {
	{
		Serial.println("Testing non-existent identity...");
		auto S0 = SA.getSession("haha");
		Serial.println(S0.toString().c_str());
		S0.Authorize(EA_SECRET_PLAINTEXT,"Test!");
		Serial.println(S0.toString().c_str());
	}

	{
		Serial.println("Testing plain-text password authentication...");
		auto S1 = SA.getSession("test");
		Serial.println(S1.toString().c_str());
		S1.Authorize(EA_SECRET_PLAINTEXT,"Test?");
		Serial.println(S1.toString().c_str());
		S1.Authorize(EA_SECRET_PLAINTEXT,"Test!");
		Serial.println(S1.toString().c_str());
	}

	{
		Serial.println("Testing HTTPDigest authentication (MD5, QoP = None)...");
		auto S2 = SA.getSession("test");
		Serial.println(S2.toString().c_str());
		String realm = "Test";
		String nonce = "123";
		String qop = "";
		String cnonce = "";
		String nc = "";
		String method = "GET";
		String uri = "/test.htm";

		String HashStr;
		HashStr.concat('?');
		HashStr.concat(';');
		HashStr.concat(realm);
		HashStr.concat(';');
		HashStr.concat(nonce);
		HashStr.concat(';');
		HashStr.concat(qop);
		HashStr.concat(';');
		HashStr.concat(cnonce);
		HashStr.concat(';');
		HashStr.concat(nc);
		HashStr.concat(';');
		HashStr.concat(method);
		HashStr.concat(';');
		HashStr.concat('"');
		HashStr.concat(uri);
		//HashStr.concat('"');
		S2.Authorize(EA_SECRET_HTTPDIGESTAUTH_MD5,std::move(HashStr));
		Serial.println(S2.toString().c_str());

		HashStr = "test:"+realm+":Test?";
		char HA1[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
		Serial.printf("- HA1: %s\n", String(HA1,32).c_str());

		HashStr = method+':'+uri;
		char HA2[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA2);
		Serial.printf("- HA2: %s\n", String(HA2,32).c_str());

		HashStr.clear();
		HashStr.concat(HA1,32);
		HashStr.concat(':');
		HashStr.concat(nonce);
		HashStr.concat(':');
		HashStr.concat(HA2,32);
		char RESP[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP);
		Serial.printf("- RESP: %s\n", String(RESP,32).c_str());

		HashStr.clear();
		HashStr.concat(RESP,32);
		HashStr.concat(';');
		HashStr.concat(realm);
		HashStr.concat(';');
		HashStr.concat(nonce);
		HashStr.concat(';');
		HashStr.concat(qop);
		HashStr.concat(';');
		HashStr.concat(cnonce);
		HashStr.concat(';');
		HashStr.concat(nc);
		HashStr.concat(';');
		HashStr.concat(method);
		HashStr.concat(';');
		HashStr.concat('"');
		HashStr.concat(uri);
		HashStr.concat('"');
		S2.Authorize(EA_SECRET_HTTPDIGESTAUTH_MD5,std::move(HashStr));
		Serial.println(S2.toString().c_str());

		HashStr = "test:"+realm+":Test!";
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
		Serial.printf("- HA1: %s\n", String(HA1,32).c_str());
		Serial.printf("- HA2: %s\n", String(HA2,32).c_str());

		HashStr.clear();
		HashStr.concat(HA1,32);
		HashStr.concat(':');
		HashStr.concat(nonce);
		HashStr.concat(':');
		HashStr.concat(HA2,32);
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP);
		Serial.printf("- RESP: %s\n", String(RESP,32).c_str());

		HashStr.clear();
		HashStr.concat(RESP,32);
		HashStr.concat(';');
		HashStr.concat(realm);
		HashStr.concat(';');
		HashStr.concat(nonce);
		HashStr.concat(';');
		HashStr.concat(qop);
		HashStr.concat(';');
		HashStr.concat(cnonce);
		HashStr.concat(';');
		HashStr.concat(nc);
		HashStr.concat(';');
		HashStr.concat(method);
		HashStr.concat(';');
		HashStr.concat('"');
		HashStr.concat(uri);
		HashStr.concat('"');
		S2.Authorize(EA_SECRET_HTTPDIGESTAUTH_MD5,std::move(HashStr));
		Serial.println(S2.toString().c_str());
	}

	{
		Serial.println("Testing HTTPDigest authentication (MD5-SESS, QoP = None)...");
		auto S3 = SA.getSession("test");
		Serial.println(S3.toString().c_str());
		String realm = "Test";
		String method = "GET";
		String uri = "/test.htm";
		String nonce = "123";
		String qop = "";
		String cnonce = "234";
		String nc = "";

		String HashStr;
		HashStr = "test:"+realm+":Test!";
		char HA1[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
		HashStr.clear();
		HashStr.concat(HA1,32);
		HashStr.concat(':');
		HashStr.concat(nonce);
		HashStr.concat(':');
		HashStr.concat(cnonce);
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
		Serial.printf("- HA1: %s\n", String(HA1,32).c_str());

		HashStr = method+':'+uri;
		char HA2[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA2);
		Serial.printf("- HA2: %s\n", String(HA2,32).c_str());

		HashStr.clear();
		HashStr.concat(HA1,32);
		HashStr.concat(':');
		HashStr.concat(nonce);
		HashStr.concat(':');
		HashStr.concat(HA2,32);
		char RESP[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP);
		Serial.printf("- RESP: %s\n", String(RESP,32).c_str());

		HashStr.clear();
		HashStr.concat(RESP,32);
		HashStr.concat(';');
		HashStr.concat(realm);
		HashStr.concat(';');
		HashStr.concat(nonce);
		HashStr.concat(';');
		HashStr.concat(qop);
		HashStr.concat(';');
		HashStr.concat(cnonce);
		HashStr.concat(';');
		HashStr.concat(nc);
		HashStr.concat(';');
		HashStr.concat(method);
		HashStr.concat(';');
		HashStr.concat('"');
		HashStr.concat(uri);
		HashStr.concat('"');
		S3.Authorize(EA_SECRET_HTTPDIGESTAUTH_MD5SESS,std::move(HashStr));
		Serial.println(S3.toString().c_str());
	}

	{
		Serial.println("Testing HTTPDigest authentication (MD5, QoP = auth)...");
		auto S3 = SA.getSession("test");
		Serial.println(S3.toString().c_str());
		String realm = "Test";
		String method = "GET";
		String uri = "/test.htm";
		String nonce = "123";
		String qop = "auth";
		String cnonce = "234";
		String nc = "12";

		String HashStr;
		HashStr = "test:"+realm+":Test!";
		char HA1[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA1);
		Serial.printf("- HA1: %s\n", String(HA1,32).c_str());

		HashStr = method+':'+uri;
		char HA2[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),HA2);
		Serial.printf("- HA2: %s\n", String(HA2,32).c_str());

		HashStr.clear();
		HashStr.concat(HA1,32);
		HashStr.concat(':');
		HashStr.concat(nonce);
		HashStr.concat(':');
		HashStr.concat(nc);
		HashStr.concat(':');
		HashStr.concat(cnonce);
		HashStr.concat(':');
		HashStr.concat(qop);
		HashStr.concat(':');
		HashStr.concat(HA2,32);
		char RESP[32];
		Serial.printf("- MD5(%s)\n", HashStr.c_str());
		textMD5_LC((uint8_t*)HashStr.begin(),HashStr.length(),RESP);
		Serial.printf("- RESP: %s\n", String(RESP,32).c_str());

		HashStr.clear();
		HashStr.concat(RESP,32);
		HashStr.concat(';');
		HashStr.concat(realm);
		HashStr.concat(';');
		HashStr.concat(nonce);
		HashStr.concat(';');
		HashStr.concat(qop);
		HashStr.concat(';');
		HashStr.concat(cnonce);
		HashStr.concat(';');
		HashStr.concat(nc);
		HashStr.concat(';');
		HashStr.concat(method);
		HashStr.concat(';');
		HashStr.concat('"');
		HashStr.concat(uri);
		HashStr.concat('"');
		S3.Authorize(EA_SECRET_HTTPDIGESTAUTH_MD5,std::move(HashStr));
		Serial.println(S3.toString().c_str());
	}
	
  delay(100000);
}
