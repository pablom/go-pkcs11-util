
package pkcs11util

import (
	_ "crypto"
	"crypto/x509"
	"crypto/rsa"
	"fmt"
	"errors"
	"math/big"
	"github.com/pablom/go-pkcs11"
	"github.com/grantae/certinfo"
	certigo "github.com/square/certigo/lib"
)

type pkcs11Certificate struct {
	cert *x509.Certificate
	label	string
	cka_id []byte
}

type pkcs11PrivateKey struct {

	//publicKey crypto.PublicKey

	// The an ObjectHandle pointing to the private key on the HSM
	privateKeyHandle pkcs11.ObjectHandle

	label	string
	cka_id []byte
}

/****************************************************************************************
*  Match certificate by public key
*****************************************************************************************/
func (crt pkcs11Certificate) matchCertByPublicKey(pk rsa.PublicKey) (bool) {
	rsaPublicKey := crt.cert.PublicKey.(*rsa.PublicKey)
	return rsaPublicKey.N.Cmp(pk.N) == 0 && rsaPublicKey.E == pk.E
}
/****************************************************************************************
*  Print out certificate
*****************************************************************************************/
func (crt pkcs11Certificate) Print() {
	// Print the certificate
	result, err := certinfo.CertificateText(crt.cert)
	if err != nil {
		return
	}
	fmt.Printf("PKCS11 object label [%s]:\n", crt.label)
	fmt.Print(result)
}
/****************************************************************************************
*  Print out certificates list
*****************************************************************************************/
func PrintCertificateList(certs []*pkcs11Certificate) {
	for _, crt := range certs {
		crt.Print()
	}
}
/****************************************************************************************
*  Get list of all available private RSA key inside HSM
*****************************************************************************************/
func GetRsaPrivateKeyList(p *pkcs11.Ctx, session pkcs11.SessionHandle) ([]*pkcs11PrivateKey, error) {
	var v []*pkcs11PrivateKey

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA)}

	/* Init find certificates function */
	if err := p.FindObjectsInit(session, template); err != nil {
		return nil, err
	}

	/* Try to find objects (certificates) */
	objs, _, err := p.FindObjects(session, pkcs11.CK_MAXOBJ)
	if err != nil {
		return nil, err
	}

	/* Stop to find objects */
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, err
	}

	for _, obj := range objs {
		templatePk := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil)}

		attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(obj), templatePk)
		if err != nil {
			continue
		}

		/* Add certificate to the slice */
		v = append(v, &pkcs11PrivateKey{
			privateKeyHandle:	pkcs11.ObjectHandle(obj),
			label:      		string(attr[0].Value),
			cka_id:     		attr[1].Value,
		})
	}

	return v, nil
}
/****************************************************************************************
*  Get list of all available certificates inside HSM
*****************************************************************************************/
func GetCertificateList(p *pkcs11.Ctx, session pkcs11.SessionHandle) ([]*pkcs11Certificate, error) {
	var v []*pkcs11Certificate
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}

	/* Init find certificates function */	
	if err := p.FindObjectsInit(session, template); err != nil {
		return nil, err
	}

	/* Try to find objects (certificates) */
	objs, _, err := p.FindObjects(session, pkcs11.CK_MAXOBJ)
	if err != nil {
		return nil, err
	}

	/* Stop to find objects */
	if err := p.FindObjectsFinal(session); err != nil {
		return nil, err
	}

	for _, obj := range objs {
		templateCrt := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil)}

		attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(obj), templateCrt)
		if err != nil {
			continue
		}
		/* Create X509 Certificate from CKA_VALUE attribute */
		certs, err := x509.ParseCertificates(attr[1].Value)
		if err != nil || len(certs) != 1 {
			continue
		}
		/* Add certificate to the slice */
		v = append(v, &pkcs11Certificate{
			cert:       certs[0],
			label:      string(attr[0].Value),
			cka_id:     attr[2].Value,
		})
	}

	return v, nil
}
/****************************************************************************************
*  Try to find mathched certificate by private key
****************************************************************************************/
func findCertificateByPrivateKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, pk pkcs11.ObjectHandle, certs []*pkcs11Certificate) (crt *pkcs11Certificate, err error) {

	template_pk := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil)}

	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(pk), template_pk)
	if err != nil {
		return nil, err
	}

	if certs == nil {
		certs, err = GetCertificateList(p, session)
		if err != nil {
			return nil, err
		} else if len(certs) == 0 {
			err = errors.New("p11util: empty certificate's list")
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("p11util: empty certificate's list")
	}

	// Create RSA public key from modulus & exponent
	rsa_pub_pk := rsa.PublicKey{new(big.Int).SetBytes(attr[1].Value), int(new(big.Int).SetBytes(attr[2].Value).Int64())}

	for _, crt := range certs {
		if crt.matchCertByPublicKey(rsa_pub_pk) {
			return crt, nil
		}
	}

	return nil, errors.New("p11util: couldn't find certificate by private key")
}
/****************************************************************************************
*  Sort certificates by serial number
****************************************************************************************/
func sortCerts() (certs []*pkcs11Certificate) {
/*
	verbose("Sorting certificates by serial number...", 3)

	var serials []string
	certsBySerial := map[string]*x509.Certificate{}

	for c, _ := range CERTS {
		s := fmt.Sprintf("%0x", c.SerialNumber)
		serials = append(serials, s)
		certsBySerial[s] = c
	}

	sort.Strings(serials)

	for _, s := range serials {
		verbose(fmt.Sprintf("Adding (in order): %s", s), 4)
		certs = append(certs, certsBySerial[s])
	}
*/
	return
}
/****************************************************************************************
*  Build certificate's chain
****************************************************************************************/
func buildCertificateChain(certs_lst []*pkcs11Certificate, crts_chain *[]*pkcs11Certificate) {

	/* Get last certificate in the chain */
	cert_chain := (*crts_chain)[len(*crts_chain)-1]

	for _, crt := range certs_lst {
		/* Skip to check the same certificate */
		if cert_chain.cert.Equal(crt.cert) {
			continue
		}

		if err := cert_chain.cert.CheckSignatureFrom(crt.cert); err == nil {
			/* Add current certificate to the chain */
			*crts_chain = append( (*crts_chain), crt)
			/* Skip continue find if certificate is self signed */
			if certigo.IsSelfSigned(crt.cert) {
				return
			}
			/* Continue to build certificates chain */
			buildCertificateChain(certs_lst,  crts_chain)
			return
		}
	}
}
/****************************************************************************************
*  Try to find private key by label
****************************************************************************************/
func FindRsaPrivateKeyByLabel(p *pkcs11.Ctx, session pkcs11.SessionHandle, pkLabel string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA)}

	if err := p.FindObjectsInit(session, template); err != nil {
		return 0, err
	}
	objs, _, err := p.FindObjects(session, pkcs11.CK_MAXOBJ)
	if err != nil {
		return 0, err
	}
	if err := p.FindObjectsFinal(session); err != nil {
		return 0, err
	}

	for _,obj := range objs {
		templatePk := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil)}
		attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(obj), templatePk)
		if err != nil {
			continue
		}

		if pkLabel == string(attr[0].Value) {
			return pkcs11.ObjectHandle(obj), nil
		}
	}
	/* Private key is not found */
	return 0, errors.New("Couldn't find private key by label [%s]", pkLabel)
}
/****************************************************************************************
*  Try to find certificate's chain by private key (label)
****************************************************************************************/
func FindRsaPrivateKeyCertificateChainByLabel(p *pkcs11.Ctx, session pkcs11.SessionHandle, pk_label string, certs []*pkcs11Certificate) ([]*pkcs11Certificate, error) {
	var crt_chain []*pkcs11Certificate

	pk, err := FindRsaPrivateKeyByLabel(p, session,pk_label)
	if err != nil {
		return nil, err
	}

	if certs == nil {
		certs, err = GetCertificateList(p, session)
		if err != nil {
			return nil, err
		} else if len(certs) == 0 {
			return nil, errors.New("p11util: empty certificate's list")
		}
	}

	pk_cert, err := findCertificateByPrivateKey(p, session, pkcs11.ObjectHandle(pk), nil)
	if err != nil {
		return nil, err
	}
	/* Append certificate from private key */
	crt_chain = append(crt_chain, pk_cert)

	/* Check if that certificate is self signed, just return certificates chain */
	if certigo.IsSelfSigned(pk_cert.cert) {
		return crt_chain, nil
	}

	buildCertificateChain(certs, &crt_chain)

	return crt_chain, nil
}