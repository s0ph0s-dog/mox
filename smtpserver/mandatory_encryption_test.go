package smtpserver

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/mail"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func random_choices(input_set string, output_len int) string {
	intcap := big.NewInt(int64(len(input_set)))
	var result bytes.Buffer
	for range output_len {
		choice, err := rand.Int(rand.Reader, intcap)
		if err != nil {
			panic(err)
		}
		result.WriteByte(input_set[choice.Int64()])
	}
	return result.String()
}

func default_domain() string {
	return "chat.example"
}

func make_account() (string, string) {
	const alphanumeric = "abcdefghijklmnopqrstuvwxyz0123456789"
	domain := default_domain()
	user := fmt.Sprintf("ac_%s@%s", random_choices(alphanumeric, 10), domain)
	password := random_choices(alphanumeric, 16)
	return user, password
}

type emlctx struct {
	FromAddr string
	ToAddr   string
	Subject  string
}

func emlctx_default_subject(from_addr string, to_addr string) emlctx {
	return emlctx{from_addr, to_addr, "..."}
}

func loademailmsg(filename string, ctx emlctx) *mail.Message {
	path := filepath.Join("..", "testdata", "smtpserverencrypted", filename)
	t, err := template.ParseFiles(path)
	if err != nil {
		panic(err)
	}
	var tmpl bytes.Buffer
	err = t.Execute(&tmpl, &ctx)
	if err != nil {
		panic(err)
	}
	msg, err := mail.ReadMessage(&tmpl)
	if err != nil {
		panic(err)
	}
	return msg
}

/*
func loademail(cm *ChatmailMilter, filename string, ctx emlctx) {
	msg := loademailmsg(filename, ctx)
	var bodycopy bytes.Buffer
	cm.mimeFrom = msg.Header.Get("From")
	cm.secureJoinHdr = msg.Header.Get("Secure-Join")
	cm.subject = msg.Header.Get("Subject")
	cm.content_type = msg.Header.Get("Content-Type")
	_, err := bodycopy.ReadFrom(msg.Body)
	if err != nil {
		panic(err)
	}
	cm.body = &bodycopy
}
*/

/*
func setenvelope(cm *ChatmailMilter, mailFrom string, rcptTos []string) {
	cm.mailFrom = mailFrom
	cm.rcptTos = rcptTos
}
*/

func test_is_valid_encrypted_message(filename string, ctx emlctx) (bool, error) {
	msg := loademailmsg(filename, ctx)
	return IsValidEncryptedMessage(ctx.Subject, msg.Header.Get("Content-Type"), msg.Body)
}

func test_is_valid_securejoin_message(filename string, ctx emlctx) (bool, error) {
	msg := loademailmsg(filename, ctx)
	return IsValidSecureJoinMessage(msg.Header.Get("Content-Type"), msg.Header.Get("Secure-Join"), msg.Body)
}

func test_validate_encrypted_message(filename string, ctx emlctx) (bool, error) {
	mox.Conf.Dynamic.Chatmail.Enabled = true
	msg := loademailmsg(filename, ctx)
	from, err := smtp.ParseAddress(ctx.FromAddr)
	if err != nil {
		return false, fmt.Errorf("The test address %s is not a valid email address.", ctx.FromAddr)
	}
	rcptAddr, err := smtp.ParseAddress(ctx.ToAddr)
	if err != nil {
		return false, fmt.Errorf("The test address %s is not a valid email address.", ctx.ToAddr)
	}
	rcpt := recipient{
		smtp.Path{
			Localpart: rcptAddr.Localpart,
			IPDomain: dns.IPDomain{
				Domain: rcptAddr.Domain,
			},
		},
		nil,
		nil,
	}
	return ValidateEncryptedEmail(
		ctx.Subject,
		msg.Header.Get("Content-Type"),
		msg.Header.Get("Secure-Join"),
		from,
		[]recipient{rcpt},
		msg.Body,
	)
}

/*
func TestMilterRejectForgedFromAddr(t *testing.T) {
	from_addr, _ := make_account()
	recipient, _ := make_account()
	to_addr, _ := make_account()
	cm := make_milter()
	setenvelope(&cm, from_addr, []string{recipient})
	loademail(&cm, "plain.eml", emlctx_default_subject(from_addr, to_addr))

	result, err := cm.ValidateEmail()
	want := milter.RespAccept
	if err != nil || result != want {
		t.Fatalf("ValidateEmail() with normal headers = %q, %v; want %q, nil", result, err, want)
	}

	loademail(&cm, "plain.eml", emlctx_default_subject("forged@c3.testrun.org", to_addr))
	result, err = cm.ValidateEmail()
	want = milter.RespReject
	if err != nil || result != want {
		t.Fatalf("ValidateEmail() with forged from = %q, %v; want %q, nil", result, err, want)
	}
}
*/

func TestEncryptionRejectUnencryptedMail(t *testing.T) {
	from_addr := "a@external.example"
	to_addr := "b@external.example"
	subject := "..."
	ctx := emlctx{from_addr, to_addr, subject}

	result, err := test_is_valid_encrypted_message("plain.eml", ctx)
	want := false
	if err != nil || result != want {
		t.Fatalf("IsValidEncryptedMessage() with plain message = %t, %v; want %t, nil", result, err, want)
	}

	result, err = test_is_valid_encrypted_message("fake-encrypted.eml", ctx)
	want = false
	if err != nil || result != want {
		t.Fatalf("IsValidEncryptedMessage() with fake encrypted message = %t, %v; want %t, nil", result, err, want)
	}
}

func TestEncryptionSecurejoinMessages(t *testing.T) {
	from_addr := "a@external.example"
	to_addr := "b@external.example"
	subject := "..."
	ctx := emlctx{from_addr, to_addr, subject}

	// Real Securejoin message, which should be accepted.
	result, err := test_is_valid_securejoin_message("securejoin-vc.eml", ctx)
	want := true
	if err != nil || result != want {
		t.Fatalf("IsValidSecureJoinMessage() with real SecureJoin message = %t, %v; want %t, nil", result, err, want)
	}

	// Fake Securejoin message with the headers, but spam contents.
	result, err = test_is_valid_securejoin_message("securejoin-vc-fake.eml", ctx)
	want = false
	if err != nil || result != want {
		t.Fatalf("IsValidSecureJoinMessage() with fake SecureJoin message = %t, %v; want %t, nil", result, err, want)
	}
}

func TestEncryptionAcceptEncryptedEmailWithAllCommonSubjects(t *testing.T) {
	for _, subj := range CommonEncryptedSubjects {
		ctx := emlctx{
			"1@external.example",
			"2@external.example",
			subj,
		}
		result, err := test_is_valid_encrypted_message("encrypted.eml", ctx)
		want := true
		if err != nil || result != want {
			t.Fatalf("IsValidEncryptedMessage() with valid message and common subject = %t, %v; want %t, nil", result, err, want)
		}
	}
	ctx := emlctx{
		"1@external.example",
		"2@external.example",
		"Click this link!",
	}
	result, err := test_is_valid_encrypted_message("encrypted.eml", ctx)
	want := false
	if err != nil || result != want {
		t.Fatalf("IsValidEncryptedMessage() with valid message and uncommon subject = %t, %v; want %t, nil", result, err, want)
	}
}

func TestEncryptionRejectLiteralOpenPGPPackets(t *testing.T) {
	ctx := emlctx_default_subject("1@external.example", "2@external.example")
	result, err := test_is_valid_encrypted_message("literal.eml", ctx)
	want := false
	if err != nil || result != want {
		t.Fatalf("IsValidEncryptedMessage() with literal OpenPGP packet = %t, %v; want %t, nil", result, err, want)
	}
}

func TestEncryptionRejectUnencryptedDeliveryNotifications(t *testing.T) {
	from_addr, _ := make_account()
	to_addr, _ := make_account()
	to_addr += ".org"
	ctx := emlctx_default_subject(from_addr, to_addr)
	result, err := test_is_valid_encrypted_message("mdn.eml", ctx)
	want := false
	if err != nil || result != want {
		t.Fatalf("IsValidEncryptedMessage() with unencrypted MDN = %t, %v; want %t, nil", result, err, want)
	}
}

func TestEncryptionAcceptToPrivacyAddress(t *testing.T) {
	from_addr, _ := make_account()
	to_addr := "privacy@testrun.org"
	mox.Conf.Dynamic.Chatmail.AllowPlaintextTo = append(mox.Conf.Dynamic.Chatmail.AllowPlaintextTo, to_addr)
	ctx := emlctx_default_subject(from_addr, to_addr)
	result, err := test_validate_encrypted_message("plain.eml", ctx)
	want := true
	if err != nil || result != want {
		t.Fatalf("ValidateEncryptedEmail() with privacy@ = %t, %v; want %t, nil", result, err, want)
	}

	invalid_to_addr := "privacy@another.example"
	ctx = emlctx_default_subject(from_addr, invalid_to_addr)
	result, err = test_validate_encrypted_message("plain.eml", ctx)
	want = false
	if err != nil || result != want {
		t.Fatalf("ValidateEncryptedEmail() with invalid privacy@ = %t, %v; want %t, nil", result, err, want)
	}

}

func TestEncryptionAllowAutocryptSetupMessage(t *testing.T) {
	from_addr, _ := make_account()
	to_addr := from_addr

	ctx := emlctx{from_addr, to_addr, "Autocrypt Setup Message"}
	result, err := test_validate_encrypted_message("asm.eml", ctx)
	want := true
	if err != nil || result != want {
		t.Fatalf("ValidateEncryptedEmail() with valid Autocrypt Setup Message = %t, %v; want %t, nil", result, err, want)
	}

}

// TODO: port test_cleartext_send_fails
// TODO: port test_cleartext_incoming_fails
// TODO: port test_cleartext_incoming_mailer_daemon

func TestEncryptionPassthroughSender(t *testing.T) {
	from_addr, _ := make_account()
	to_addr := "someone@external.example"
	mox.Conf.Dynamic.Chatmail.AllowPlaintextFrom = append(mox.Conf.Dynamic.Chatmail.AllowPlaintextTo, from_addr)
	ctx := emlctx_default_subject(from_addr, to_addr)
	result, err := test_validate_encrypted_message("plain.eml", ctx)

	want := true
	if err != nil || result != want {
		t.Fatalf("ValidateEncryptedEmail() with passthrough sender = %t, %v, want %t, nil", result, err, want)
	}
}

func TestEncryptionArmoredPayload(t *testing.T) {
	payload := "-----BEGIN PGP MESSAGE-----\r\n" +
		"\r\n" +
		"HELLOWORLD\r\n" +
		"-----END PGP MESSAGE-----\r\n" +
		"\r\n"
	if IsValidEncryptedPayload(payload) {
		t.Fatal("accepted garbage PGP payload")
	}

	payload = "-----BEGIN PGP MESSAGE-----\r\n" +
		"\r\n" +
		"=njUN\r\n" +
		"-----END PGP MESSAGE-----\r\n" +
		"\r\n"
	if IsValidEncryptedPayload(payload) {
		t.Fatal("accepted PGP payload with only CRC24")
	}

	payload = "-----BEGIN PGP MESSAGE-----\r\n" +
		"\r\n" +
		"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\r\n" +
		"=b5Kp\r\n" +
		"-----END PGP MESSAGE-----\r\n" +
		"\r\n"
	if !IsValidEncryptedPayload(payload) {
		t.Fatal("rejected valid PGP payload")
	}
}
