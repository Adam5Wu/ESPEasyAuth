// This demo requires a modified ESP8266 Arduino, found here:
// https://github.com/Adam5Wu/Arduino

// This demo requires ZWUtils-Arduino library, found here:
// https://github.com/Adam5Wu/ZWUtils-Arduino

#include "ESPEasyAuth.h"

DummySessionAuthority DSA;

void setup() {
  Serial.begin(115200);
	Serial.println();
}

void loop() {
	Serial.println("Testing dummy identity...");
	auto S1 = DSA.getSession("test");
	Serial.println(S1.toString().c_str());
	Serial.println("Testing dummy authorization...");
	S1.Authorize(EA_SECRET_PLAINTEXT,"Test!");
	Serial.println(S1.toString().c_str());
	
  delay(100000);
}
