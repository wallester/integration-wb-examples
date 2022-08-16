package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

const PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDLets8+7M+iAQAqN/5BVyCIjhTQ4cmXulL+gm3v0oGMWzLupUS
v8KPA+Tp7dgC/DZPfMLaNH1obBBhJ9DhS6RdS3AS3kzeFrdu8zFHLWF53DUBhS92
5dCAEuJpDnNizdEhxTfoHrhuCmz8l2nt1pe5eUK2XWgd08Uc93h5ij098wIDAQAB
AoGAHLaZeWGLSaen6O/rqxg2laZ+jEFbMO7zvOTruiIkL/uJfrY1kw+8RLIn+1q0
wLcWcuEIHgKKL9IP/aXAtAoYh1FBvRPLkovF1NZB0Je/+CSGka6wvc3TGdvppZJe
rKNcUvuOYLxkmLy4g9zuY5qrxFyhtIn2qZzXEtLaVOHzPQECQQDvN0mSajpU7dTB
w4jwx7IRXGSSx65c+AsHSc1Rj++9qtPC6WsFgAfFN2CEmqhMbEUVGPv/aPjdyWk9
pyLE9xR/AkEA2cGwyIunijE5v2rlZAD7C4vRgdcMyCf3uuPcgzFtsR6ZhyQSgLZ8
YRPuvwm4cdPJMmO3YwBfxT6XGuSc2k8MjQJBAI0+b8prvpV2+DCQa8L/pjxp+VhR
Xrq2GozrHrgR7NRokTB88hwFRJFF6U9iogy9wOx8HA7qxEbwLZuhm/4AhbECQC2a
d8h4Ht09E+f3nhTEc87mODkl7WJZpHL6V2sORfeq/eIkds+H6CJ4hy5w/bSw8tjf
sz9Di8sGIaUbLZI2rd0CQQCzlVwEtRtoNCyMJTTrkgUuNufLP19RZ5FpyXxBO5/u
QastnN77KfUwdj3SJt44U/uh1jAIv4oSLBr8HYUkbnI8
-----END RSA PRIVATE KEY-----`

func GenerateAuthJWT(apiKey string, privateKey *rsa.PrivateKey) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"api_key": apiKey,
		"ts":      time.Now().Unix(),
	}).SignedString(privateKey)
}

func ParsePrivateKey(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func main() {
	privateKey, err := ParsePrivateKey([]byte(PrivateKey))
	if err != nil {
		panic(err)
	}

	// New token must be generated before each request because token lifetime - 5 seconds
	jwt, err := GenerateAuthJWT("vpf1ksw75ijcGiOQOaOZKKuYqUjwaMONqYEqcJNqbMzxZal8tKuNQvaFf3DceZhZ3d8jOsjTeK03VtN7QJS6Igrasv8jOmKfdfxy", privateKey)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("GET", "http://localhost:8888/v1/pricing-plan-types", nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("Authorization", "Bearer "+jwt)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	// "ok"
	fmt.Println(res)
}
