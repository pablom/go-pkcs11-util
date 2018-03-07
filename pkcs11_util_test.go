
package p11util

import (
	"os"
	"testing"
	"github.com/pablom/go-pkcs11"
	//certigo "github.com/square/certigo/lib"
	_ "github.com/grantae/certinfo"
	"fmt"
	//"crypto/tls"
)

import "github.com/DiSiqueira/GoTree"

func ppp() {
	var artist gotree.GTStructure
	artist.Name = "Pantera"

	var album gotree.GTStructure
	album.Name = "Far Beyond Driven"

	var music gotree.GTStructure
	music.Name = "5 Minutes Alone"

	//Add Music to the Album
	album.Items = append(album.Items, music)

	//Add Album to the Artist
	artist.Items = append(artist.Items, album)

	gotree.PrintTree(artist)
}



func setenv(t *testing.T) *pkcs11.Ctx {
	os.Setenv("ET_PTKC_SW_DATAPATH", "/home/pm/cryptoki/cryptoki64")
	lib := "/opt/eracom-5.2.0/lib/linux-x86_64/libctsw.so"
	t.Logf("loading %s", lib)
	p := pkcs11.New(lib)
	if p == nil {
		t.Fatal("Failed to init lib")
	}
	return p
}

func getSession(p *pkcs11.Ctx, t *testing.T) pkcs11.SessionHandle {
	if err := p.Initialize(); err != nil {
		t.Fatalf("init error %s\n", err)
	}
	slots, err := p.GetSlotList(true)
	if err != nil {
		t.Fatalf("slots %s\n", err)
	}
	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("session %s\n", err)
	}
	if err := p.Login(session, pkcs11.CKU_USER, "qwerty"); err != nil {
		t.Fatalf("user pin %s\n", err)
	}
	return session
}

func finishSession(p *pkcs11.Ctx, session pkcs11.SessionHandle) {
	p.Logout(session)
	p.CloseSession(session)
	p.Finalize()
	p.Destroy()
}

func TestNotFindRsaPrivakeKey(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	obj,err := FindRsaPrivateKeyByLabel(p, session,"PRIVKEY_NOT_FOUND")
	if err == nil {
		t.Fatalf("Failed to find RSA private key: %s\n", err)
	}
	if obj != 0 {
		t.Fatal("RSA private key [PRIVKEY_NOT_FOUND] found\n")
	}
}

func TestFindRsaPrivakeKey(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	obj,err := FindRsaPrivateKeyByLabel(p, session,"OWOC")
	if err != nil {
		t.Fatalf("Failed to find RSA private key: %s\n", err)
	}
	if obj == 0 {
		t.Fatal("Couldn't find RSA private key [OWOC]\n")
	}
}

func TestGetRsaPrivateKeyList(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	privkeys, err := GetRsaPrivateKeyList(p, session)
	fmt.Printf("Found (%d) RSA private key(s)\n", len(privkeys))
	if err != nil {
		t.Fatalf("Failed to get RSA private keys list: %s\n", err)
	}

	//certAndKey := tls.Certificate{}
}

func TestGetCertificateList(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	certs, err := GetCertificateList(p, session)
	fmt.Printf("Found (%d) certificate(s)\n", len(certs))
	if err != nil {
		t.Fatalf("Failed to get certificate's list: %s\n", err)
	}

	//PrintCertificateList(certs)
}

func TestFindRsaPrivateKeyCertificateChain(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
/*
	certs_chain, err := FindRsaPrivateKeyCertificateChainByLabel(p,session,"OWBANK", nil)
	if err != nil {
		t.Fatalf("Failed to find certificate's chain by RSA private key: %s\n", err)
	}
*/
	fmt.Printf("=================================================\n")
	ppp()
	//PrintCertificateList(certs_chain)
}

