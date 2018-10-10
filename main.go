package main

import (
	"bufio"
	"bytes"
	"crypto/dsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strings"

	"github.com/coyim/gotrax"
	"github.com/otrv4/ed448"
)

var itag uint32
var publicKey *gotrax.PublicKey

func main() {
	flag.Parse()

	if *itagFlag != "" {
		val, _ := hex.DecodeString(*itagFlag)
		itag = binary.BigEndian.Uint32(val)
	}

	if *publicKeyFlag != "" {
		val, _ := hex.DecodeString(*publicKeyFlag)
		_, k2, ok := gotrax.DeserializePoint(val)
		if ok {
			publicKey = gotrax.CreatePublicKey(k2, gotrax.Ed448Key)
		}
	}

	for _, ff := range flag.Args() {
		processFile(ff)
	}

	processStdin()
}

func banner(name string) {
	fmt.Printf("%%%%%%%%%%%%%%%% %-30s %%%%%%%%%%%%%%%%\n", name)
}

func processFile(filename string) {
	banner(fmt.Sprintf("File: %s", filename))
	file, e := os.Open(filename)
	if e != nil {
		return
	}
	defer file.Close()
	processReader(file)
}

func processStdin() {
	info, err := os.Stdin.Stat()
	if err != nil || (info.Mode()&os.ModeCharDevice) != 0 {
		return
	}

	banner("STDIN")
	processReader(os.Stdin)
}

func processReader(r io.Reader) {
	buf, e := ioutil.ReadAll(r)
	if e != nil {
		return
	}

	if !processPidginFile(buf) {
		if !processPrekeyServerFile(buf) {
			fmt.Printf("FAILURE TO PROCESS FILE\n")
		}
	}
	fmt.Println()
}

func tryAsPrekeyServerClientProfile(b []byte) ([]byte, bool) {
	cp := new(gotrax.ClientProfile)
	rest, ok := cp.Deserialize(b)
	if !ok {
		return b, false
	}

	valid := "UNKNOWN"
	if itag != uint32(0) {
		ee := cp.Validate(itag)
		if ee == nil {
			valid = "VALID"
		} else {
			valid = fmt.Sprintf("INVALID: %v", ee)
		}
	}

	fmt.Printf("Client Profile v4 {\n")
	fmt.Printf("  Instance tag: %08x\n", cp.InstanceTag)
	fmt.Printf("  Public key:  %s\n", formatPublicKey(cp.PublicKey))
	fmt.Printf("  Forging key: %s\n", formatPublicKey(cp.ForgingKey))
	fmt.Printf("  Versions: %s\n", formatVersions(cp.Versions))
	fmt.Printf("  Expiration: %v\n", cp.Expiration)
	fmt.Printf("  DSA Key: %s\n", formatDSAKey(cp.DsaKey))
	fmt.Printf("  Transitional signature: %s\n", formatTransitionalSignature(cp.TransitionalSignature))
	fmt.Printf("  Signature: %s\n", formatSignature(cp.Sig))
	fmt.Printf("  Valid: %s\n", valid)
	fmt.Printf("}\n")

	return rest, true
}

func tryAsPrekeyServerPrekeyProfile(b []byte) ([]byte, bool) {
	pp := new(gotrax.PrekeyProfile)
	rest, ok := pp.Deserialize(b)
	if !ok {
		return b, false
	}

	valid := "(UNKNOWN)"
	if itag != uint32(0) && publicKey != nil {
		ee := pp.Validate(itag, publicKey)
		if ee == nil {
			valid = "VALID"
		} else {
			valid = fmt.Sprintf("INVALID: %v", ee)
		}
	}

	fmt.Printf("Prekey Profile v4 {\n")
	fmt.Printf("  Instance tag: %08x\n", pp.InstanceTag)
	fmt.Printf("  Expiration: %v\n", pp.Expiration)
	fmt.Printf("  Shared prekey: %s\n", formatPublicKey(pp.SharedPrekey))
	fmt.Printf("  Signature: %s\n", formatSignature(pp.Sig))
	fmt.Printf("  Valid: %s\n", valid)
	fmt.Printf("}\n")
	return rest, true
}

func tryAsPrekeyServerPrekeyMessage(b []byte) ([]byte, bool) {
	pm := new(gotrax.PrekeyMessage)
	rest, ok := pm.Deserialize(b)
	if !ok {
		fmt.Printf("ugh bla\n")
		return b, false
	}

	valid := "(UNKNOWN)"
	if itag != uint32(0) {
		ee := pm.Validate(itag)
		if ee == nil {
			valid = "VALID"
		} else {
			valid = fmt.Sprintf("INVALID: %v", ee)
		}
	}

	fmt.Printf("Prekey Message v4 {\n")
	fmt.Printf("  Identifier: %08x\n", pm.Identifier)
	fmt.Printf("  Instance tag: %08x\n", pm.InstanceTag)
	fmt.Printf("  Y: %x\n", gotrax.SerializePoint(pm.Y))
	fmt.Printf("  B: %x\n", pm.B.Bytes())
	fmt.Printf("  Valid: %s\n", valid)
	fmt.Printf("}\n")
	return rest, true
}

func tryAsPidginClientProfile(ident, data string) bool {
	decoded, e := base64.StdEncoding.DecodeString(data)
	if e != nil {
		return false
	}
	cp := new(gotrax.ClientProfile)
	rest, ok := cp.Deserialize(decoded)
	if !ok {
		return false
	}

	idents := strings.SplitN(ident, ":", 2)
	if len(idents) < 2 {
		return false
	}
	proto, acc := idents[0], idents[1]

	shouldPublish := rest[0] == 1
	valid := "UNKNOWN"
	if itag != uint32(0) {
		ee := cp.Validate(itag)
		if ee == nil {
			valid = "VALID"
		} else {
			valid = fmt.Sprintf("INVALID: %v", ee)
		}
	}

	fmt.Printf("-> %s, %s\n", proto, acc)
	fmt.Printf("Client Profile v4 {\n")
	fmt.Printf("  Instance tag: %08x\n", cp.InstanceTag)
	fmt.Printf("  Public key:  %s\n", formatPublicKey(cp.PublicKey))
	fmt.Printf("  Forging key: %s\n", formatPublicKey(cp.ForgingKey))
	fmt.Printf("  Versions: %s\n", formatVersions(cp.Versions))
	fmt.Printf("  Expiration: %v\n", cp.Expiration)
	fmt.Printf("  DSA Key: %s\n", formatDSAKey(cp.DsaKey))
	fmt.Printf("  Transitional signature: %s\n", formatTransitionalSignature(cp.TransitionalSignature))
	fmt.Printf("  Signature: %s\n", formatSignature(cp.Sig))
	fmt.Printf("  Should publish: %v\n", shouldPublish)
	fmt.Printf("  Valid: %s\n", valid)
	fmt.Printf("}\n")
	return true
}

func tryAsPidginPrekeyProfile(ident, data string) bool {
	idents := strings.SplitN(ident, ":", 2)
	if len(idents) < 2 {
		return false
	}
	proto, acc := idents[0], idents[1]
	decoded, e := base64.StdEncoding.DecodeString(data)
	if e != nil {
		return false
	}
	pp := new(gotrax.PrekeyProfile)
	rest, ok := pp.Deserialize(decoded)
	if !ok {
		return false
	}
	shouldPublish := "(UNKNOWN)"
	sym := "(UNKNOWN)"
	priv := "(UNKNOWN)"
	pub := "(UNKNOWN)"
	if len(rest) > 0 {
		shouldPublish = fmt.Sprintf("%v", rest[0] == 1)
		rest = rest[1:]
		if len(rest) >= 57 {
			var dd [57]byte
			copy(dd[:], rest)
			kp := gotrax.DeriveKeypair(dd)
			sym = fmt.Sprintf("%x", kp.Sym)
			priv = fmt.Sprintf("%x", gotrax.SerializeScalar(kp.Priv.K()))
			pub = fmt.Sprintf("%x", gotrax.SerializePoint(kp.Pub.K()))
			rest = rest[57:]
		}
	}

	valid := "(UNKNOWN)"
	if itag != uint32(0) && publicKey != nil {
		ee := pp.Validate(itag, publicKey)
		if ee == nil {
			valid = "VALID"
		} else {
			valid = fmt.Sprintf("INVALID: %v", ee)
		}
	}

	fmt.Printf("-> %s, %s\n", proto, acc)
	fmt.Printf("Prekey Profile v4 {\n")
	fmt.Printf("  Instance tag: %08x\n", pp.InstanceTag)
	fmt.Printf("  Expiration: %v\n", pp.Expiration)
	fmt.Printf("  Shared prekey: %s\n", formatPublicKey(pp.SharedPrekey))
	fmt.Printf("  Signature: %s\n", formatSignature(pp.Sig))
	fmt.Printf("  Should publish: %s\n", shouldPublish)
	fmt.Printf("  Sym:  %s\n", sym)
	fmt.Printf("  Priv: %s\n", priv)
	fmt.Printf("  Pub:  %s\n", pub)
	fmt.Printf("  Valid: %s\n", valid)
	fmt.Printf("}\n")
	return true
}

func tryAsPidginPrekeyMessage(ident, data string) bool {
	idents := strings.SplitN(ident, ":", 2)
	if len(idents) < 2 {
		return false
	}
	proto, acc := idents[0], idents[1]
	decoded, e := base64.StdEncoding.DecodeString(data)
	if e != nil {
		return false
	}
	pm := new(gotrax.PrekeyMessage)
	rest, ok := pm.Deserialize(decoded)
	if !ok {
		return false
	}
	shouldPublish := "(UNKNOWN)"
	priv_ecdh := "(UNKNOWN)"
	pub_ecdh := "(UNKNOWN)"
	priv_dh := "(UNKNOWN)"
	pub_dh := "(UNKNOWN)"

	if len(rest) > 0 {
		shouldPublish = fmt.Sprintf("%v", rest[0] == 1)
		rest = rest[1:]
		var sc ed448.Scalar
		if rest, sc, ok = gotrax.DeserializeScalar(rest); ok {
			pc := ed448.PrecomputedScalarMul(sc)
			priv_ecdh = fmt.Sprintf("%x", gotrax.SerializeScalar(sc))
			pub_ecdh = fmt.Sprintf("%x", gotrax.SerializePoint(pc))

			var pmb *big.Int
			if rest, pmb, ok = gotrax.ExtractMPI(rest); ok {
				priv_dh = fmt.Sprintf("%x", pmb.Bytes())
				pmb2 := new(big.Int).Exp(gotrax.G3, pmb, gotrax.DHP)
				pub_dh = fmt.Sprintf("%x", pmb2.Bytes())
			}
		}
	}

	valid := "(UNKNOWN)"
	if itag != uint32(0) {
		ee := pm.Validate(itag)
		if ee == nil {
			valid = "VALID"
		} else {
			valid = fmt.Sprintf("INVALID: %v", ee)
		}
	}

	fmt.Printf("-> %s, %s\n", proto, acc)
	fmt.Printf("Prekey Message v4 {\n")
	fmt.Printf("  Identifier: %08x\n", pm.Identifier)
	fmt.Printf("  Instance tag: %08x\n", pm.InstanceTag)
	fmt.Printf("  Y: %x\n", gotrax.SerializePoint(pm.Y))
	fmt.Printf("  B: %x\n", pm.B.Bytes())
	fmt.Printf("  Should publish: %s\n", shouldPublish)
	fmt.Printf("  Priv (Y): %s\n", priv_ecdh)
	fmt.Printf("  Pub (Y):  %s\n", pub_ecdh)
	fmt.Printf("  Priv (B): %s\n", priv_dh)
	fmt.Printf("  Pub (B):  %s\n", pub_dh)
	fmt.Printf("  Valid: %s\n", valid)
	fmt.Printf("}\n")
	return true
}

const emptyValue = "(NIL)"

func formatDSAKey(k *dsa.PublicKey) string {
	if k == nil {
		return emptyValue
	}
	return "(DSA key)"
}

func formatTransitionalSignature(s []byte) string {
	if s == nil {
		return emptyValue
	}
	return fmt.Sprintf("%x", s)
}

func formatSignature(s *gotrax.EddsaSignature) string {
	if s == nil {
		return emptyValue
	}
	return fmt.Sprintf("%x", s.S())
}

func formatPublicKey(k *gotrax.PublicKey) string {
	if k == nil {
		return emptyValue
	}
	return fmt.Sprintf("%x", gotrax.SerializePoint(k.K()))
}

func formatVersions(bb []byte) string {
	entries := make([]string, len(bb))
	for ix, vv := range bb {
		entries[ix] = "v" + string(vv)
	}
	return strings.Join(entries, ", ")
}

func tryAsPidginForgingKeyV4(ident, data string) bool {
	decoded, e := base64.StdEncoding.DecodeString(data)

	if e != nil {
		return false
	}

	kk := gotrax.CreatePublicKey(nil, gotrax.ForgingKey)

	if _, ok := kk.Deserialize(decoded); ok {
		idents := strings.SplitN(ident, ":", 2)
		if len(idents) < 2 {
			return false
		}
		proto, acc := idents[0], idents[1]

		fmt.Printf("-> %s, %s\n", proto, acc)
		fmt.Printf("Forging Key v4 {\n")
		fmt.Printf("  Pub:  %x\n", gotrax.SerializePoint(kk.K()))
		fmt.Printf("}\n")

		return true
	} else {
		return false
	}
}

func tryAsPidginPrivateKeyV4(ident, data string) bool {
	decoded, e := base64.StdEncoding.DecodeString(data)

	if e != nil {
		return false
	}

	if len(decoded) != 57 {
		return false
	}

	var dd [57]byte
	copy(dd[:], decoded)

	kp := gotrax.DeriveKeypair(dd)

	idents := strings.SplitN(ident, ":", 2)
	if len(idents) < 2 {
		return false
	}
	proto, acc := idents[0], idents[1]

	fmt.Printf("-> %s, %s\n", proto, acc)
	fmt.Printf("Private Key v4 {\n")
	fmt.Printf("  Sym:  %x\n", kp.Sym)
	fmt.Printf("  Priv: %x\n", gotrax.SerializeScalar(kp.Priv.K()))
	fmt.Printf("  Pub:  %x\n", gotrax.SerializePoint(kp.Pub.K()))
	fmt.Printf("}\n")

	return true
}

func processPidginFile(b []byte) bool {
	sc := bufio.NewScanner(bytes.NewBuffer(b))
	for sc.Scan() {
		ident := sc.Text()
		if sc.Scan() {
			data := sc.Text()
			if !(tryAsPidginClientProfile(ident, data) ||
				tryAsPidginPrivateKeyV4(ident, data) ||
				tryAsPidginPrekeyProfile(ident, data) ||
				tryAsPidginPrekeyMessage(ident, data) ||
				tryAsPidginForgingKeyV4(ident, data)) {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func processPrekeyServerFile(b []byte) bool {
	_, ok := tryAsPrekeyServerClientProfile(b)
	if ok {
		return true
	}
	_, ok = tryAsPrekeyServerPrekeyProfile(b)
	if ok {
		return true
	}
	_, ok = tryAsPrekeyServerPrekeyMessage(b)
	if ok {
		return true
	}
	return false
}
