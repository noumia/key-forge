package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

// Ticker master
type Ticker struct {
	PubkeyVersion     byte
	PrikeyVersion     byte
	ScriptHashVersion byte
}

// Tickers map
var Tickers map[string]Ticker

func init() {
	Tickers = map[string]Ticker{
		"btc":  {PubkeyVersion: 0, PrikeyVersion: 128, ScriptHashVersion: 5},
		"ltc":  {PubkeyVersion: 48, PrikeyVersion: 176, ScriptHashVersion: 50},
		"zny":  {PubkeyVersion: 81, PrikeyVersion: 128, ScriptHashVersion: 5},
		"mona": {PubkeyVersion: 50, PrikeyVersion: 176, ScriptHashVersion: 55},
		"tbtc": {PubkeyVersion: 111, PrikeyVersion: 239, ScriptHashVersion: 196},
		"tltc": {PubkeyVersion: 111, PrikeyVersion: 239, ScriptHashVersion: 58},
	}
}

// Trans transaction
type Trans struct {
	Ticket       string
	Ticker       string
	ScriptHash   string
	PubkeyHash   string
	RedeemScript string

	Secret   string
	LockHash string

	LimitTime int64

	Vin  []string
	Vout []string

	VoHash string

	Hint []string
}

func readTrans(r io.Reader) (*Trans, error) {
	var trans Trans

	d := json.NewDecoder(r)

	err := d.Decode(&trans)
	if err != nil {
		return nil, err
	}

	return &trans, nil
}

func reverse(numbers []byte) {
	for i, j := 0, len(numbers)-1; i < j; i, j = i+1, j-1 {
		numbers[i], numbers[j] = numbers[j], numbers[i]
	}
}

func writeHex(buf *bytes.Buffer, text string) {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		log.Fatal(err)
	}
	buf.Write(bytes)
}

func writeTX(buf *bytes.Buffer, text string) {
	bytes, err := hex.DecodeString(text)
	if err != nil {
		log.Fatal(err)
	}
	reverse(bytes)
	buf.Write(bytes)
}

func writeI4(buf *bytes.Buffer, v uint32) {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, v)
	buf.Write(bytes)
}

func writeV(buf *bytes.Buffer, v int) {
	if v < 0xfd {
		buf.WriteByte(byte(v))
	} else if v <= 0xffff {
		buf.WriteByte(byte(v & 0xff))
		buf.WriteByte(byte((v >> 8) & 0xff))
	} else {
		log.Fatal("large.V")
	}
}

func writeSC(buf *bytes.Buffer, bytes []byte) {
	writeV(buf, len(bytes))
	buf.Write(bytes)
}

func writeP(buf *bytes.Buffer, bytes []byte) {
	sz := len(bytes)
	if sz <= 75 {
		buf.WriteByte(byte(sz))
	} else if sz < 0xff {
		buf.WriteByte(0x4c) // OP_PUSHDATA1
		buf.WriteByte(byte(sz))
	} else {
		log.Fatal("large.P")
	}
	buf.Write(bytes)
}

func makeVHash(trans *Trans) string {
	buf := &bytes.Buffer{}

	bytes, err := base64.RawURLEncoding.DecodeString(trans.Ticket)
	if err != nil {
		log.Fatal(err)
	}

	buf.Write(bytes)

	for _, v := range trans.Vout {
		vout, ver, err := CheckDecode(v)
		if err != nil {
			log.Fatal(err)
		}
		if ver != verVOUT || len(vout) != 28 {
			log.Fatal("malformed.vout")
		}

		buf.Write(vout)
	}

	hash := Hash160(buf.Bytes())
	data := append(hash, byte(21))

	return base64.RawURLEncoding.EncodeToString(data)
}

func makeHead(trans *Trans, scs [][]byte, n, seq int) []byte {
	buf := &bytes.Buffer{}

	writeI4(buf, 1) // version

	writeV(buf, len(trans.Vin))

	for i, v := range trans.Vin {
		txs := strings.SplitN(v, ":", 2)
		if len(txs) != 2 {
			log.Fatal("malformed.tx")
		}
		txid := txs[0]
		vout, err := strconv.Atoi(txs[1])
		if err != nil {
			log.Fatal(err)
		}

		writeTX(buf, txid)
		writeI4(buf, uint32(vout))

		if n < 0 {
			writeSC(buf, scs[i])
		} else if i == n {
			writeSC(buf, scs[0])
		} else {
			writeV(buf, 0)
		}

		writeI4(buf, uint32(seq))
	}

	return buf.Bytes()
}

func makeTail(trans *Trans, lockTime int64) []byte {
	buf := &bytes.Buffer{}

	writeV(buf, len(trans.Vout))

	for _, v := range trans.Vout {
		vout, ver, err := CheckDecode(v)
		if err != nil {
			log.Fatal(err)
		}
		if ver != verVOUT || len(vout) != 28 {
			log.Fatal("malformed.vout")
		}

		buf.Write(vout[0:8])
		buf.WriteByte(25)
		buf.WriteByte(0x76) // OP_DUP
		buf.WriteByte(0xa9) // OP_HASH160
		buf.WriteByte(20)
		buf.Write(vout[8:28])
		buf.WriteByte(0x88) // OP_EQUALVERIFY
		buf.WriteByte(0xac) // OP_CHECKSIG
	}

	writeI4(buf, uint32(lockTime))

	return buf.Bytes()
}

const sigAll = 0x01

var sigAlls = []byte{sigAll, 0, 0, 0}

func makeSinature(trans *Trans, tail, sc []byte, key Signer, seq int) ([][]byte, error) {
	scs := [][]byte{sc}

	sigs := make([][]byte, 0)

	for i := 0; i < len(trans.Vin); i++ {
		head := makeHead(trans, scs, i, seq)

		data0 := append(head, tail...)
		data1 := append(data0, sigAlls...)

		sig, err := key.Sign(Hash256(data1))
		if err != nil {
			return nil, err
		}

		sigs = append(sigs, append(sig, sigAll))
	}

	return sigs, nil
}

func makeScript(trans *Trans, sigs [][]byte, pubkey, sc, secret []byte) ([][]byte, error) {
	redeem := (len(secret) > 0)

	scs := make([][]byte, 0)

	for i := 0; i < len(sigs); i++ {
		buf := &bytes.Buffer{}

		writeP(buf, sigs[i])
		writeP(buf, pubkey)

		if redeem {
			writeP(buf, secret)
			buf.WriteByte(0x51) // OP_TRUE
		} else {
			buf.WriteByte(0x00) // OP_FALSE
		}

		writeP(buf, sc)

		scs = append(scs, buf.Bytes())
	}

	return scs, nil
}

func sign(privateKey string, j bool) error {
	trans, err := readTrans(os.Stdin)
	if err != nil {
		return err
	}

	/* */

	t, ok := Tickers[trans.Ticker]
	if !ok {
		return errors.New("malformed.ticker")
	}

	vHash := makeVHash(trans)
	if vHash != trans.VoHash {
		return errors.New("malformed.vout")
	}

	/* */

	redeem := (trans.Secret != "")

	secret := []byte{}
	seq := 0xffffffff
	lockTime := int64(0)
	if redeem {
		sec, ver, err := CheckDecode(trans.Secret)
		if err != nil {
			return err
		}
		if ver != verSECRET {
			return errors.New("malformed.secret")
		}
		secret = sec
	} else {
		seq--
		lockTime = trans.LimitTime + 1
	}

	/* */

	keyBytes, ver, err := CheckDecode(privateKey)
	if err != nil {
		return err
	}

	if ver != t.PrikeyVersion {
		return errors.New("malformed.key")
	}

	key, err := NewSigner(keyBytes)
	if err != nil {
		return err
	}

	pubBytes := key.PublicBytes()
	pubkeyHash := Hash160(pubBytes)
	pubkey := CheckEncode(pubkeyHash, t.PubkeyVersion)

	if pubkey != trans.PubkeyHash {
		pubBytes = key.PublicBytesAlt()
		pubkeyHash = Hash160(pubBytes)
		pubkey = CheckEncode(pubkeyHash, t.PubkeyVersion)

		if pubkey != trans.PubkeyHash {
			return errors.New("mismatch.pubkey")
		}
	}

	/* */

	tail := makeTail(trans, lockTime)

	sc, err := hex.DecodeString(trans.RedeemScript)
	if err != nil {
		return err
	}

	sigs, err := makeSinature(trans, tail, sc, key, seq)
	if err != nil {
		return err
	}

	scs, err := makeScript(trans, sigs, pubBytes, sc, secret)
	if err != nil {
		return err
	}

	head := makeHead(trans, scs, -1, seq)

	/* */

	tx := append(head, tail...)

	rawTx := hex.EncodeToString(tx)

	if j {
		body := map[string]string{
			"rawtx": rawTx,
		}
		json, err := json.Marshal(body)
		if err != nil {
			return err
		}
		fmt.Println(string(json))
	} else {
		fmt.Println(rawTx)
	}

	/* */

	return nil
}

/* */

func generate(ticker string) error {
	t, ok := Tickers[ticker]
	if !ok {
		return errors.New("unknown.ticker")
	}

	key, err := NewKey()
	if err != nil {
		return err
	}

	keyBytes := key.PrivateBytes()
	pubBytes := key.PublicBytes()

	pubkeyHash := Hash160(pubBytes)

	prikey := CheckEncode(keyBytes, t.PrikeyVersion)
	pubkey := CheckEncode(pubkeyHash, t.PubkeyVersion)

	body := struct {
		PrivateKey string
		PubkeyHash string
	}{PrivateKey: prikey, PubkeyHash: pubkey}

	json, err := json.Marshal(body)
	if err != nil {
		return err
	}

	fmt.Println(string(json))

	return nil
}

const sizSECRET = 32
const verSECRET = 0
const verDIGEST = 41
const verVOUT = 186

func secret() error {
	bytes := make([]byte, sizSECRET)

	_, err := rand.Reader.Read(bytes)
	if err != nil {
		return err
	}

	secret := CheckEncode(bytes, verSECRET)

	digest := CheckEncode(Hash160(bytes), verDIGEST)

	body := struct {
		Secret string
		Hash   string
	}{Secret: secret, Hash: digest}

	json, err := json.Marshal(body)
	if err != nil {
		return err
	}

	fmt.Println(string(json))

	return nil
}

func main() {
	var err error

	var s bool
	var j bool
	var key string
	var ticker string

	flag.BoolVar(&s, "s", true, "Generate a secret")
	flag.BoolVar(&j, "j", false, "Output json format")
	flag.StringVar(&ticker, "t", "", "Ticker for generating key pair")
	flag.StringVar(&key, "k", "", "Private Key for signing")

	flag.Parse()

	if ticker != "" {
		err = generate(ticker)
	} else if key != "" {
		err = sign(key, j)
	} else if s {
		err = secret()
	}

	if err != nil {
		log.Fatal(err)
	}
}

/* */
