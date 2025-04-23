package smtpserver

import (
	"io"
	"mime"
	"mime/multipart"
	"encoding/base64"
	"strings"
	"slices"

	"github.com/mjl-/mox/mox-"
	"github.com/mjl-/mox/smtp"
)

// Copied from
// https://github.com/chatmail/server/blob/main/chatmaild/src/chatmaild/common_encrypted_subjects.py

var CommonEncryptedSubjects = []string{
	"...",
	"[...]",
	"암호화된 메시지",
	"Ĉifrita mesaĝo",
	"Courriel chiffré",
	"Dulrituð skilaboð",
	"Encrypted Message",
	"Fersifere berjocht",
	"Kemennadenn enrineget",
	"Krüptitud kiri",
	"Krypterat meddelande",
	"Krypteret besked",
	"Kryptert melding",
	"Mensagem criptografada",
	"Mensagem encriptada",
	"Mensaje cifrado",
	"Mensaxe cifrada",
	"Mesaj Criptat",
	"Mesazh i Fshehtëzuar",
	"Messaggio criptato",
	"Messaghju cifratu",
	"Missatge encriptat",
	"Neges wedi'i Hamgryptio",
	"Pesan terenkripsi",
	"Salattu viesti",
	"Şifreli İleti",
	"Šifrēta ziņa",
	"Šifrirana poruka",
	"Šifrirano sporočilo",
	"Šifruotas laiškas",
	"Tin nhắn được mã hóa",
	"Titkosított üzenet",
	"Verschlüsselte Nachricht",
	"Versleuteld bericht",
	"Zašifrovaná zpráva",
	"Zaszyfrowana wiadomość",
	"Zifratu mezua",
	"Κρυπτογραφημένο μήνυμα",
	"Зашифроване повідомлення",
	"Зашифрованное сообщение",
	"Зашыфраваны ліст",
	"Криптирано съобщение",
	"Шифрована порука",
	"დაშიფრული წერილი",
	"הודעה מוצפנת",
	"پیام رمزنگاری‌شده",
	"رسالة مشفّرة",
	"എൻക്രിപ്റ്റുചെയ്‌ത സന്ദേശം",
	"加密邮件",
	"已加密的訊息",
	"暗号化されたメッセージ",
}


func IsEncryptedOpenPGPPayload(payload []byte) bool {
	i := 0
	for i < len(payload) {
		// Permit only OpenPGP formatted binary data.
		if payload[i]&0xC0 != 0xC0 {
			return false
		}
		packet_type_id := payload[i] & 0x3F
		i += 1
		var body_len int
		if payload[i] < 192 {
			body_len = int(payload[i])
			i += 1
		} else if payload[i] < 224 {
			if (i + 1) >= len(payload) {
				return false
			}
			body_len = ((int(payload[i]) - 192) << 8) + int(payload[i+1]) + 192
			i += 2
		} else if payload[i] == 255 {
			if (i + 4) >= len(payload) {
				return false
			}
			body_len = (int(payload[i+1]) << 24) | (int(payload[i+2]) << 16) | (int(payload[i+3]) << 8) | int(payload[i+4])
			i += 5
		} else {
			return false
		}
		i += body_len
		if i == len(payload) {
			// The last packet in the stream should be
			// "Symmetrically Encrypted and Integrity Protected Data Packet
			// (SEIDP)".
			// This is the only place in this function that is allowed to return
			// true.
			return packet_type_id == 18
		} else if packet_type_id != 1 && packet_type_id != 3 {
			return false
		}
	}
	return false
}

func IsValidEncryptedPayload(payload string) bool {
	const header = "-----BEGIN PGP MESSAGE-----\r\n\r\n"
	const footer = "-----END PGP MESSAGE-----\r\n\r\n"
	hasHeader := strings.HasPrefix(payload, header)
	hasFooter := strings.HasSuffix(payload, footer)
	if !(hasHeader && hasFooter) {
		return false
	}
	start_idx := len(header)
	crc24_start := strings.LastIndex(payload, "=")
	var end_idx int
	if crc24_start < 0 {
		end_idx = len(payload) - len(footer)
	} else {
		end_idx = crc24_start
	}
	b64_encoded := payload[start_idx:end_idx]
	b64_decoded := make([]byte, base64.StdEncoding.DecodedLen(len(b64_encoded)))
	n, err := base64.StdEncoding.Decode(b64_decoded, []byte(b64_encoded))
	if err != nil {
		return false
	}
	b64_decoded = b64_decoded[:n]
	return IsEncryptedOpenPGPPayload(b64_decoded)
}

func IsValidEncryptedMessage(subject string, content_type string, body io.Reader) (bool, error) {
	if !slices.Contains(CommonEncryptedSubjects, subject) {
		return false, nil
	}
	mediatype, params, err := mime.ParseMediaType(content_type)
	if err != nil {
		return false, err
	}
	if mediatype != "multipart/encrypted" {
		return false, nil
	}
	mpr := multipart.NewReader(body, params["boundary"])
	// TODO: figure out how to/whether it's necessary to decode non-UTF-8 encodings
	parts_count := 0
	for {
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		if parts_count == 0 {
			part_content_type := part.Header.Get("Content-Type")
			if part_content_type != "application/pgp-encrypted" {
				return false, nil
			}
			part_body, err := io.ReadAll(part)
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(string(part_body)) != "Version: 1" {
				return false, nil
			}
		} else if parts_count == 1 {
			part_content_type := part.Header.Get("Content-Type")
			if !strings.HasPrefix(part_content_type, "application/octet-stream") {
				return false, nil
			}
			part_body, err := io.ReadAll(part)
			if err != nil {
				return false, err
			}
			if !IsValidEncryptedPayload(string(part_body)) {
				return false, nil
			}
		} else {
			return false, nil
		}
		parts_count += 1
	}
	return true, nil
}

func IsValidSecureJoinMessage(content_type string, secureJoinHdr string, body io.Reader) (bool, error) {
	if secureJoinHdr != "vc-request" && secureJoinHdr != "vg-request" {
		return false, nil
	}
	mediatype, params, err := mime.ParseMediaType(content_type)
	if err != nil {
		return false, err
	}
	if !strings.HasPrefix(mediatype, "multipart/") {
		return false, nil
	}
	mpr := multipart.NewReader(body, params["boundary"])
	parts_count := 0
	for {
		part, err := mpr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		parts_count += 1
		if parts_count > 1 {
			return false, nil
		}
		part_content_type := part.Header.Get("Content-Type")
		if strings.HasPrefix(part_content_type, "multipart/") {
			return false, nil
		}
		partmtype, _, err := mime.ParseMediaType(part_content_type)
		if err != nil {
			return false, err
		}
		if partmtype != "text/plain" {
			return false, nil
		}
		part_body, err := io.ReadAll(part)
		if err != nil {
			return false, err
		}
		// TODO: decode non-utf-8 encodings.
		part_body_str := string(part_body)
		normalized_body := strings.ToLower(strings.TrimSpace(part_body_str))
		if normalized_body != "secure-join: vc-request" && normalized_body != "secure-join: vg-request" {
			return false, nil
		}
	}
	return true, nil
}

// Check whether an email is permitted under the current Chatmail settings.
// This means either:
// - The email is validly PGP-encrypted; or
// - The email is a reasonable-looking SecureJoin request; or
// - The sender is on the plaintext allow-list; or
// - All of the recipients are on the plaintext allow-list; or
// - The email is a plausible self-addressed Autocrypt setup message.
//
// Callers should always check the error return value before considering the
// boolean.  When error is non-nil, there was an error reading the arguments,
// probably the body.  In this case, a temporary SMTP error should be returned
// to the client.
// The boolean return value is true when the email should be allowed, and false
// when the email should be rejected with SMTP 523 Encryption Required.
func ValidateEncryptedEmail(subject, content_type, secureJoinHdr string, mailFrom smtp.Address, rcptTos []recipient, body io.Reader) (bool, error) {
	confDynamic := mox.Conf.DynamicConfig()
	if !confDynamic.Chatmail.Enabled {
		return true, nil
	}
	from_str := mailFrom.String()
	if slices.Contains(confDynamic.Chatmail.AllowPlaintextFrom, from_str) {
		return true, nil
	}
	mail_encrypted, err := IsValidEncryptedMessage(
		subject,
		content_type,
		body,
	)
	if err != nil {
		return false, err
	}
	mail_securejoin, err := IsValidSecureJoinMessage(content_type, secureJoinHdr, body)
	if err != nil {
		return false, err
	}
	if mail_encrypted || mail_securejoin {
		return true, nil
	}
	if len(rcptTos) == 1 && rcptTos[0].Addr.String() == mailFrom.String() {
		if subject == "Autocrypt Setup Message" {
			if content_type == "multipart/mixed" {
				return true, nil
			}
		}
	}
	for _, recipient := range rcptTos {
		recipient_str := recipient.Addr.String()
		if from_str == recipient_str {
			continue
		}
		if slices.Contains(confDynamic.Chatmail.AllowPlaintextTo, recipient_str) {
			continue
		}
		return false, nil
	}
	return true, nil
}
