package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	rand "math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gospider007/tools"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

type PeetTlsInfo struct {
	Donate      string `json:"donate"`
	Ip          string `json:"ip"`
	HttpVersion string `json:"http_version"`
	Method      string `json:"method"`
	UserAgent   string `json:"user_agent"`
	Tls         struct {
		Ciphers    []string `json:"ciphers"`
		Extensions []struct {
			Name                       string   `json:"name"`
			ServerName                 string   `json:"server_name,omitempty"`
			Versions                   []string `json:"versions,omitempty"`
			Data                       string   `json:"data,omitempty"`
			EllipticCurvesPointFormats []string `json:"elliptic_curves_point_formats,omitempty"`
			Protocols                  []string `json:"protocols,omitempty"`
			MasterSecretData           string   `json:"master_secret_data,omitempty"`
			ExtendedMasterSecretData   string   `json:"extended_master_secret_data,omitempty"`
			StatusRequest              struct {
				CertificateStatusType   string `json:"certificate_status_type"`
				ResponderIdListLength   int    `json:"responder_id_list_length"`
				RequestExtensionsLength int    `json:"request_extensions_length"`
			} `json:"status_request,omitempty"`
			Algorithms      []string `json:"algorithms,omitempty"`
			SupportedGroups []string `json:"supported_groups,omitempty"`
			SharedKeys      []struct {
				TLSGREASE0X5A5A    string `json:"TLS_GREASE (0x5a5a),omitempty"`
				X25519MLKEM7684588 string `json:"X25519MLKEM768 (4588),omitempty"`
				X2551929           string `json:"X25519 (29),omitempty"`
			} `json:"shared_keys,omitempty"`
			PSKKeyExchangeMode  string   `json:"PSK_Key_Exchange_Mode,omitempty"`
			SignatureAlgorithms []string `json:"signature_algorithms,omitempty"`
		} `json:"extensions"`
		TlsVersionRecord     string `json:"tls_version_record"`
		TlsVersionNegotiated string `json:"tls_version_negotiated"`
		Ja3                  string `json:"ja3"`
		Ja3Hash              string `json:"ja3_hash"`
		Ja4                  string `json:"ja4"`
		Ja4R                 string `json:"ja4_r"`
		Peetprint            string `json:"peetprint"`
		PeetprintHash        string `json:"peetprint_hash"`
		ClientRandom         string `json:"client_random"`
		SessionId            string `json:"session_id"`
	} `json:"tls"`
	Http2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
		SentFrames            []struct {
			FrameType string   `json:"frame_type"`
			Length    int      `json:"length"`
			Settings  []string `json:"settings,omitempty"`
			Increment int      `json:"increment,omitempty"`
			StreamId  int      `json:"stream_id,omitempty"`
			Headers   []string `json:"headers,omitempty"`
			Flags     []string `json:"flags,omitempty"`
			Priority  struct {
				Weight    int `json:"weight"`
				DependsOn int `json:"depends_on"`
				Exclusive int `json:"exclusive"`
			} `json:"priority,omitempty"`
		} `json:"sent_frames"`
	} `json:"http2"`
	Tcpip struct {
		Ip struct {
		} `json:"ip"`
		Tcp struct {
		} `json:"tcp"`
	} `json:"tcpip"`
}

var template = `{
  "donate": "Please consider donating to keep this API running. Visit https://tls.peet.ws",
  "ip": "188.253.4.207:36307",
  "http_version": "h2",
  "method": "GET",
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
  "tls": {
    "ciphers": [
      "TLS_GREASE (0xBABA)",
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_256_CBC_SHA"
    ],
    "extensions": [
      {
        "name": "TLS_GREASE (0x2a2a)"
      },
      {
        "name": "server_name (0)",
        "server_name": "tls.peet.ws"
      },
      {
        "name": "supported_versions (43)",
        "versions": [
          "TLS_GREASE (0x1a1a)",
          "TLS 1.3",
          "TLS 1.2"
        ]
      },
      {
        "name": "extensionRenegotiationInfo (boringssl) (65281)",
        "data": "00"
      },
      {
        "name": "ec_point_formats (11)",
        "elliptic_curves_point_formats": [
          "0x00"
        ]
      },
      {
        "name": "signed_certificate_timestamp (18)"
      },
      {
        "name": "extensionEncryptedClientHello (boringssl) (65037)",
        "data": "00000100019d0020e8adf2613f8a113fe7c8f5030cc68970f5ef1033bae128039a31ef8af3fdd16b00f093193d7fd51dc58d8189aad9be4609f9456af61f40206c194cbe56296f2813139daa349b6b95606a8c812b7f28010871680398dbba208e915e86e655065717b0c29cb7ee4871e9394fd4435fb6bd1fa87270a9eca0eef64b243deeee95058aef8e4a72ccd7a91d604e69f4880d241a3ccb56d4557d439926ee9615dbfbf1c069754e20d059b2b508bb4995e9739dfe3426ffe0bbe6df17ec001033ca0c7fab409fd1cbedf299c4d994d20e56fa71f7df563714547acdcfc80b307d2f591dfecc179d8a6141ecaf52a110ed2395c8f56da8e2ab7e658656dcc8fd4c7dc8f284d8b367fa0b73e0c5ae798bad1e4b791f66"
      },
      {
        "name": "application_settings (17613)",
        "protocols": [
          "h2"
        ]
      },
      {
        "name": "extended_master_secret (23)",
        "master_secret_data": "",
        "extended_master_secret_data": ""
      },
      {
        "name": "status_request (5)",
        "status_request": {
          "certificate_status_type": "OSCP (1)",
          "responder_id_list_length": 0,
          "request_extensions_length": 0
        }
      },
      {
        "name": "application_layer_protocol_negotiation (16)",
        "protocols": [
          "h2",
          "http/1.1"
        ]
      },
      {
        "name": "compress_certificate (27)",
        "algorithms": [
          "brotli (2)"
        ]
      },
      {
        "name": "supported_groups (10)",
        "supported_groups": [
          "TLS_GREASE (0x5a5a)",
          "X25519MLKEM768 (4588)",
          "X25519 (29)",
          "P-256 (23)",
          "P-384 (24)"
        ]
      },
      {
        "name": "key_share (51)",
        "shared_keys": [
          {
            "TLS_GREASE (0x5a5a)": "00"
          },
          {
            "X25519MLKEM768 (4588)": "6940c114b7c3c0aaa4835711dd5aa20a24b8c9466e41b646b1857ddbb0c80948ca936ba21411cdab8702ae339e3c4333d3034ebf105757c45d9190214445aad26abb74e120d048b6508433c5b13ceef7ca211b0c6bc3aa5e404db92aa34b33a5f5742985b33420629c19eaa917d07f6493be4d25648fbb300595b8b266ab3c2c383cf11b8dc1cfd0d21a3a7768ed96c238f39294eb3e40d3a360b22c04d864884b87674964b2323060caa690200bdd41320be2a547f41f8e2a81267059ceac92ac297e5d4762a76828a7180169eb970c25bb6e739d68d8147e497f9d920630c43a0d78363df002fb6abaf9e98888182d26c27db25929d04ca36baa7824905e90168b8c1cb27f38901143b2c245a6693168ae462576b24f291585bb3731bd465c01a772c66a0c28331f1b602d92a11d7e6ca4c4887db6bc42ff624a8609514e5a46140c79f215286d732df61b900af15f2805a4c1202305766ddeb4027c211266662dbe290d7757c6df5495ec86b748592ee9b8b8a167cd30236f843c337621048424c52a8aa918f9af333b86a4c8b0ceb1cb7b016b3f13c64f78069eb0cdae168cf15b9ac4166ba04aa0378b448c1184e60237c68b4bc63ba9f99a107fe1448a207ef7d0abbd64ac9b490d4c4cc1cdf04b37e89e20785bbbb1ce459ace9c8a5051369233762d3d89a1a4b25f727521aac3103a4bc0fbab8341f60bc66894a3f5374a54a7bf129f72b482dba12871f9920782ce57f8202e901a85070b62b64bea8501cd6caf31c9beaa9a4f5a4a8b83c918669b26c8c69927b518755cb0fee552e27b8b0d660732f0cab531099e2494be7c63db2b80c2897ee54066e8927e63568dd470a373106e7f4c5d4f77a12b865398eb6fcb77b5a3cc81b4ec1ca9898ea65751d403641af62810043f9958876a4b5615d9b45269c6d0e431267b945bb0cbbbf418751a321d513eea606aa39176bd290968e0689e1503ad12a606699e81aa621b768f01478a2c69407f71a86222c0c7db422bfa37e1b6a8b14bbcb05c5c0ae1673b5b01798c7c39ab217907c6f8363a85a02a6e5857a2fc5429aa21e3564d98b03cf3d84c2fec64b1f1402f5b0260a90cd0579d88e8754ef0509b82757dc66ed6776d5dda5c88c3084068ae5f16935415bf69245ed7b5961edcb34d656348e4b64f866179a6692696a013b74cc9906d17f39fa72c90ff9c5e6d3b4c62aac71e944d91e0321aa1755946a794c136ba026e322a326e7a69080989144b9477e9c2907950a15accc6b566d2e276ed45bb5d14218a1170abfcb988e46f245723a16881f4fb075bf6413af9322c8cacc52b53857c3d3c7c4b2cc4624c0c0aa5c7263ebca2928c610231aebc409b3097a69ff504024338a7c90470923553f02bbbe823ac3ac122691e35408a6dac073e9ab4894b7db0a088e6e3a827b371497a083f3007c17c1162d14b088638bc81ad973836d8126c96336b4d17a67fc61acd8c1583b56c8fa311aed8c9c35861d17b4ac88b723ba5236f959342160826442f0851a7adc0a29ce22122c6c24bc4146af3350a85b0ea06b9b8c50596c5890bb96c3ab98737e5b55f9839f4a4904c2a30b1a92b86b69c25c982cd616e244562c1ab2c3253e0b04e3b2b9529294533b522fc52d45cbec068835bc675a56be5f89b5f7c8e9839ca2233dcfb78da518a5c1ff69fc1eeb7aff5bf3e46074ced13e96d7020"
          },
          {
            "X25519 (29)": "f901913f5e6fd43258f3dc01f57820c1811a3bfac442184529f5c0da07dc2c3e"
          }
        ]
      },
      {
        "name": "psk_key_exchange_modes (45)",
        "PSK_Key_Exchange_Mode": "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
      },
      {
        "name": "session_ticket (35)",
        "data": ""
      },
      {
        "name": "signature_algorithms (13)",
        "signature_algorithms": [
          "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
        ]
      },
      {
        "name": "TLS_GREASE (0x6a6a)"
      },
      {
        "name": "pre_shared_key (41)",
        "data": "0077007101b28f0b45b26936a8136b6ff3af6096f44e157c6f2241edfb1317b4755e1964ce673d73b66d314c9e9844a8a1c994070c1046f847da73dda8a0042214b76694d9fbc58f5222009d9bbba13cfa393c467de5549efd9ade610a8f0f2964ab6da8698a60d1ebbae2f6d68b6faadb6a6445379c0de82d002120383121656988eef50e2f418ac47c5c5dfcaec699f03567e3226628dfb9c64cd1"
      }
    ],
    "tls_version_record": "771",
    "tls_version_negotiated": "772",
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-43-65281-11-18-65037-17613-23-5-16-27-10-51-45-35-13-41,4588-29-23-24,0",
    "ja3_hash": "b130ef96637d5d39848550485d2d359f",
    "ja4": "t13d1517h2_8daaf6152771_7e51fdad25f2",
    "ja4_r": "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
    "peetprint": "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-41-43-45-5-51-65037-65281-GREASE-GREASE",
    "peetprint_hash": "d44d68f0fce54cd423d6792272a242b8",
    "client_random": "d5447feb3b0a1e3acc708a402d1adef9cb670f71165a394a256483594e820658",
    "session_id": "ef0e32d8dc47f658b4f4bed5e1e96eeeb6cdd52c0ab1e10eb00b83b37530c9a8"
  },
  "http2": {
    "akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "akamai_fingerprint_hash": "52d84b11737d980aef856699f885ca86",
    "sent_frames": [
      {
        "frame_type": "SETTINGS",
        "length": 24,
        "settings": [
          "HEADER_TABLE_SIZE = 65536",
          "ENABLE_PUSH = 0",
          "INITIAL_WINDOW_SIZE = 6291456",
          "MAX_HEADER_LIST_SIZE = 262144"
        ]
      },
      {
        "frame_type": "WINDOW_UPDATE",
        "length": 4,
        "increment": 15663105
      },
      {
        "frame_type": "HEADERS",
        "stream_id": 1,
        "length": 487,
        "headers": [
          ":method: GET",
          ":authority: tls.peet.ws",
          ":scheme: https",
          ":path: /api/all",
          "sec-ch-ua: \\\"Chromium\\\";v=\\\"136\\\", \\\"Google Chrome\\\";v=\\\"136\\\", \\\"Not.A/Brand\\\";v=\\\"99\\",
          "sec-ch-ua-mobile: ?0",
          "sec-ch-ua-platform: \\\"macOS\\",
          "upgrade-insecure-requests: 1",
          "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
          "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
          "sec-fetch-site: none",
          "sec-fetch-mode: navigate",
          "sec-fetch-user: ?1",
          "sec-fetch-dest: document",
          "accept-encoding: gzip, deflate, br, zstd",
          "accept-language: en,en-US;q=0.9,zh-CN;q=0.8,zh;q=0.7,ru;q=0.6",
          "priority: u=0, i"
        ],
        "flags": [
          "EndStream (0x1)",
          "EndHeaders (0x4)",
          "Priority (0x20)"
        ],
        "priority": {
          "weight": 256,
          "depends_on": 0,
          "exclusive": 1
        }
      }
    ]
  },
  "tcpip": {
    "ip": {},
    "tcp": {}
  }
}`

var template2 = `{
  "donate": "Please consider donating to keep this API running. Visit https://tls.peet.ws",
  "ip": "185.220.238.112:36079",
  "http_version": "h2",
  "method": "GET",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
  "tls": {
    "ciphers": [
      "TLS_GREASE (0xBABA)",
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_RSA_WITH_AES_256_GCM_SHA384",
      "TLS_RSA_WITH_AES_128_CBC_SHA",
      "TLS_RSA_WITH_AES_256_CBC_SHA"
    ],
    "extensions": [
      {
        "name": "TLS_GREASE (0x3a3a)"
      },
      {
        "name": "application_settings (17613)",
        "protocols": [
          "h2"
        ]
      },
      {
        "name": "server_name (0)",
        "server_name": "tls.peet.ws"
      },
      {
        "name": "ec_point_formats (11)",
        "elliptic_curves_point_formats": [
          "0x00"
        ]
      },
      {
        "name": "signature_algorithms (13)",
        "signature_algorithms": [
          "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
        ]
      },
      {
        "name": "session_ticket (35)",
        "data": ""
      },
      {
        "name": "status_request (5)",
        "status_request": {
          "certificate_status_type": "OSCP (1)",
          "responder_id_list_length": 0,
          "request_extensions_length": 0
        }
      },
      {
        "name": "signed_certificate_timestamp (18)"
      },
      {
        "name": "application_layer_protocol_negotiation (16)",
        "protocols": [
          "h2",
          "http/1.1"
        ]
      },
      {
        "name": "extended_master_secret (23)",
        "master_secret_data": "",
        "extended_master_secret_data": ""
      },
      {
        "name": "extensionRenegotiationInfo (boringssl) (65281)",
        "data": "00"
      },
      {
        "name": "key_share (51)",
        "shared_keys": [
          {
            "TLS_GREASE (0x3a3a)": "00"
          },
          {
            "X25519MLKEM768 (4588)": "10988896e803c520cbc4d0ae78c840e44a7f64ac5dd2e42e63eb8cc702555685300e62b4e8da232f80814ff133f4bb0d789c5d37b802e9b9773febb20cb14be69240147571ef574f85f45dd15b42ffc83889d6c40e7262116426858a1b2c11972b40bfe555a0e0d5128ae0898ab3bf6ce060bac0bb2f748675237b9b98026e304d3ac0839c323cc348a9f7734b310c734c8369e94a9c19f66f5cfb9d68a8461b1a22e082c48483149f38bf617a5dc866530784cf16449298e12d95c6ae48a371e79065e04263e0a2963b44112e3c8ae41a7fea459893477eb332988a845bc74cb0610941a6545690a006a8072e7a253d30ac750f9c296287a4037856794abaf75a5028fb287d703d74882fb96351346b5ea2d95d3622ac37095f6226b4281093b09c392f3a06b120cfccfb7184319582fc02c3a44a2a61b9369a4bc2f45614f31442b766f4b736c4baad19a686474a96f774b673482e5a90894d873810d3600cc1a1e3e170992654f42ab982b56a5eeb3bd307c1f33119b7f2c6bae93a92e27a02e401dda315b6db2089921dba52aab1e12192d55c3102cc84421f6f330f0166659e35392b153f79e5c9c511cbc72c52d14b7b48679a663a815fca859518b36135529820b98cbc1ef3c2c1f73b93aeea980f500d9f312797321fddb9bafc3cb37ed9552ed1c31947b1ba56cd76a7c171322c5ea66459ab492f27196351b8e36286641877336996d59bae332cae94e1b3996cc23bb5af3f6a1cda610aec9001e499cd558717730328d1906a8020227b33b59af1b137c16f73bc0d81f6c19ca96c761a24a404ceec3154e5c8252371aedcb2c603e6c787a58f23293d8466cfa70baf250277404b5363d05d0149c72c676d4715cd9ccac81306548b9aad6ac4769cb964830c7bb3351ae2625de0ec8a73ba0c8da0c249b91e818041ac39050c0b9f4be67666d0447231ba516007e5eab6b59563da62062ce9a18ada33f811b2acdcb1af989c0431c206a85b41877e7925cd7a459dfe0bbf634b34469452982aa7e01a46986c7db149075e554d025501e29a9ca0db6bd07c253e0549459968ee605757db9e675469e374680cc40388a200a563acdf38487e39548986b22c1884010b17d3c793398245bd5a8c99f0a66b784ddfe909ad09c35cd6169484129a422b01d2101638179168a136057b46d705c91586611c336934343a532bb315b0351a938e65308f352aad7b1e50f4a34f63c85f09ca0172ba4fa48722fc07d2016848398137d5ad5c39b02f6170a9e49f74425dda6465627aa30b69949b3b2c3309c8ad361f926a18286bae24353a82b05af52939e964122e4565b279299f57762b30348938916245c6c25b0a714575bbb9c8cc3268ab9a4fb98aaa62319d211c826676846976aedfeb73fca617c5f53bab496bff8385cbe078859c0207bc70dbf75657b47e6ce732fac21ad903a825c2871b681dfd0ccf54977a8262763aa2186f43627a10158736a621b39d6554225ec9991a493a9da45f75a9b3a55054986c13a7e28010105394987631c1a8b03b3da7081c8f984d80500afe4bc818593148eaad23071b31034d6bc277b1d5b357e382f6e51ee6fb84d9db77cf45a53f20255ac62ca6548fa7d5d84a1cfbd511e6f565d4e84e3924e42ad2aa1168393ee6157646b64e5c858f8c39a9d94fc63fe8336614dc7ae4f65f3d2e79ad908417ca7e9d0e36"
          },
          {
            "X25519 (29)": "82a3edc3dc041c1ddaa8abdbd0759187ffdae09c1970dafc03e3b16ba7488d7c"
          }
        ]
      },
      {
        "name": "compress_certificate (27)",
        "algorithms": [
          "brotli (2)"
        ]
      },
      {
        "name": "supported_versions (43)",
        "versions": [
          "TLS_GREASE (0x8a8a)",
          "TLS 1.3",
          "TLS 1.2"
        ]
      },
      {
        "name": "supported_groups (10)",
        "supported_groups": [
          "TLS_GREASE (0x3a3a)",
          "X25519MLKEM768 (4588)",
          "X25519 (29)",
          "P-256 (23)",
          "P-384 (24)"
        ]
      },
      {
        "name": "psk_key_exchange_modes (45)",
        "PSK_Key_Exchange_Mode": "PSK with (EC)DHE key establishment (psk_dhe_ke) (1)"
      },
      {
        "name": "extensionEncryptedClientHello (boringssl) (65037)",
        "data": "0000010001a10020307d4d2698eea58a9d56e1adfc8e3c188551047343acc574eca9061aa99d4d5900f09a1478fb3163603b7e8987cf3df34ff2f9bf7a60b5f3de6a5c4d36a8216a96055e11cd15dcf4953a05e2109e02a1864b270a28b647882523b93cb1a868df07074339eeffeab59a18b45c178a174b4bc3ad578d727faa2f4e9ed4ccef9cca33e272cc7884bc27042b0c334df204db871033dac34e01f58246e9de3f3758aa08198e206a3d158a4cdf37cd34f4887d75f101d88359b746c793035947f406f77555b6dc9cfa5973b5573f2ea4540c25625e2d87f7ff0ef220b7fc873a35ac53ce4723716ab0fe25b8486443a4a5e7ef143bdcc0b77de7724fbf569bc2ae2dbbddab579b5704f7baa44900e4cd25f2d8614d"
      },
      {
        "name": "TLS_GREASE (0x7a7a)"
      }
    ],
    "tls_version_record": "771",
    "tls_version_negotiated": "772",
    "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17613-0-11-13-35-5-18-16-23-65281-51-27-43-10-45-65037,4588-29-23-24,0",
    "ja3_hash": "ffd9d926bde32b862d99912b856d749e",
    "ja4": "t13d1516h2_8daaf6152771_8802cfb92a1f",
    "ja4_r": "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0000,0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
    "peetprint": "GREASE-772-771|2-1.1|GREASE-4588-29-23-24|1027-2052-1025-1283-2053-1281-2054-1537|1|2|GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|0-10-11-13-16-17613-18-23-27-35-43-45-5-51-65037-65281-GREASE-GREASE",
    "peetprint_hash": "1d4ffe9b0e34acac0bd883fa7f79d7b5",
    "client_random": "7f68d2dfe4870e26dcfc2d2d475a47515c547f6e5ea838c8a3e3974968720f1a",
    "session_id": "7b6a3d027927e90160ee0eb0d4e05d605714ac1bc0057833c4c40c74895b518e"
  },
  "http2": {
    "akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "akamai_fingerprint_hash": "52d84b11737d980aef856699f885ca86",
    "sent_frames": [
      {
        "frame_type": "SETTINGS",
        "length": 24,
        "settings": [
          "HEADER_TABLE_SIZE = 65536",
          "ENABLE_PUSH = 0",
          "INITIAL_WINDOW_SIZE = 6291456",
          "MAX_HEADER_LIST_SIZE = 262144"
        ]
      },
      {
        "frame_type": "WINDOW_UPDATE",
        "length": 4,
        "increment": 15663105
      },
      {
        "frame_type": "HEADERS",
        "stream_id": 1,
        "length": 496,
        "headers": [
          ":method: GET",
          ":authority: tls.peet.ws",
          ":scheme: https",
          ":path: /api/all",
          "sec-ch-ua: \\\"Chromium\\\";v=\\\"136\\\", \\\"Microsoft Edge\\\";v=\\\"136\\\", \\\"Not.A/Brand\\\";v=\\\"99\\",
          "sec-ch-ua-mobile: ?0",
          "sec-ch-ua-platform: \\\"Windows\\",
          "upgrade-insecure-requests: 1",
          "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0",
          "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
          "sec-fetch-site: none",
          "sec-fetch-mode: navigate",
          "sec-fetch-user: ?1",
          "sec-fetch-dest: document",
          "accept-encoding: gzip, deflate, br, zstd",
          "accept-language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
          "priority: u=0, i"
        ],
        "flags": [
          "EndStream (0x1)",
          "EndHeaders (0x4)",
          "Priority (0x20)"
        ],
        "priority": {
          "weight": 256,
          "depends_on": 0,
          "exclusive": 1
        }
      }
    ]
  },
  "tcpip": {
    "ip": {},
    "tcp": {}
  }
}`

type Spec struct {
	raw                []byte
	ContentType        uint8             //contentType
	MessageVersion     uint16            //MessageVersion
	HandshakeVersion   uint16            //HandshakeVersion
	HandShakeType      uint8             //HandShakeType
	RandomTime         uint32            //RandomTime
	RandomBytes        []byte            //RandomBytes
	SessionId          cryptobyte.String //sessionId
	CipherSuites       []uint16          //cipherSuites
	CompressionMethods cryptobyte.String //CompressionMethods
	Extensions         []Extension
	MapExtensions      map[uint16]cryptobyte.String
}
type Extension struct {
	Type uint16
	Data cryptobyte.String
}

func createExtension(extensionId uint16, data []byte) utls.TLSExtension {
	switch extensionId {
	case 0:
		return new(utls.SNIExtension)
	case 5:
		return new(utls.StatusRequestExtension)
	case 17:
		return new(utls.StatusRequestV2Extension)
	case 18:
		return new(utls.SCTExtension)
	case 23:
		return new(utls.ExtendedMasterSecretExtension)
	case 35:
		return new(utls.SessionTicketExtension)
	case 41:
		return new(utls.UtlsPreSharedKeyExtension)
	case 44:
		return new(utls.CookieExtension)
	case 57:
		return new(utls.QUICTransportParametersExtension)
	case 30031:
		extV := new(utls.FakeChannelIDExtension)
		extV.OldExtensionID = true
		return extV
	case 30032:
		extV := new(utls.FakeChannelIDExtension)
		return extV
	case 65037:
		return utls.BoringGREASEECH()
	default:
		ext := utls.ExtensionFromID(extensionId)
		if ext == nil {
			return &utls.GenericExtension{
				Id:   extensionId,
				Data: data,
			}
		}
		extWriter, ok := ext.(utls.TLSExtensionWriter)
		if ok {
			extWriter.Write(data)
			return ext
		}
		return &utls.GenericExtension{
			Id:   extensionId,
			Data: data,
		}
	}
}

func (obj Extension) utlsExt() utls.TLSExtension {
	return createExtension(obj.Type, obj.Data)
}

// type:  11 : utls.SupportedPointsExtension
func (obj *Spec) Points() []uint8 {
	for _, ext := range obj.Extensions {
		if ext.Type == 11 {
			ex := new(utls.SupportedPointsExtension)
			ex.Write(ext.Data)
			return ex.SupportedPoints
		}
	}
	return nil
}

// type:  16 : utls.ALPNExtension
func (obj *Spec) Protocols() []string {
	for _, ext := range obj.Extensions {
		if ext.Type == 16 {
			ex := new(utls.ALPNExtension)
			ex.Write(ext.Data)
			return ex.AlpnProtocols
		}
	}
	return nil
}

// type:  43 : utls.SupportedVersionsExtension
func (obj *Spec) Versions() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 43 {
			ex := new(utls.SupportedVersionsExtension)
			ex.Write(ext.Data)
			return ex.Versions
		}
	}
	return nil
}

// type:  13 : utls.SignatureAlgorithmsExtension
func (obj *Spec) Algorithms() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 13 {
			ex := new(utls.SignatureAlgorithmsExtension)
			ex.Write(ext.Data)
			algorithms := make([]uint16, len(ex.SupportedSignatureAlgorithms))
			for i, algorithm := range ex.SupportedSignatureAlgorithms {
				algorithms[i] = uint16(algorithm)
			}
			return algorithms
		}
	}
	return nil
}

// type:  10 : utls.SupportedCurvesExtension
func (obj *Spec) Curves() []uint16 {
	for _, ext := range obj.Extensions {
		if ext.Type == 10 {
			ex := new(utls.SupportedCurvesExtension)
			ex.Write(ext.Data)
			algorithms := make([]uint16, len(ex.Curves))
			for i, algorithm := range ex.Curves {
				algorithms[i] = uint16(algorithm)
			}
			return algorithms
		}
	}
	return nil
}
func (obj *Spec) ServerName() string {
	for _, ext := range obj.Extensions {
		if ext.Type == 0 {
			ex := new(utls.SNIExtension)
			ex.Write(ext.Data)
			return ex.ServerName
		}
	}
	return ""
}
func (obj *Spec) utlsClientHelloSpec() utls.ClientHelloSpec {
	// fingerprinter := &utls.Fingerprinter{
	// 	AllowBluntMimicry: true,
	// 	RealPSKResumption: true,
	// 	AlwaysAddPadding:  true,
	// }
	// generatedSpec, _ := fingerprinter.FingerprintClientHello(obj.raw)
	// return *generatedSpec
	var clientHelloSpec utls.ClientHelloSpec
	clientHelloSpec.CipherSuites = obj.CipherSuites
	clientHelloSpec.CompressionMethods = obj.CompressionMethods
	clientHelloSpec.Extensions = make([]utls.TLSExtension, len(obj.Extensions))
	for i, ext := range obj.Extensions {
		clientHelloSpec.Extensions[i] = ext.utlsExt()
	}
	clientHelloSpec.GetSessionID = sha256.Sum256
	return clientHelloSpec
}
func (obj *Spec) Bytes() []byte {
	return obj.raw
}
func (obj *Spec) Hex() string {
	return tools.Hex(obj.Bytes())
}
func (obj *Spec) Map() map[string]any {
	extensions := make([]map[string]any, len(obj.Extensions))
	for i, ext := range obj.Extensions {
		extensions[i] = map[string]any{
			"type": ext.Type,
			"data": tools.Hex(ext.Data),
		}
	}
	results := map[string]any{
		"points":         obj.Points(),
		"protocols":      obj.Protocols(),
		"versions":       obj.Versions(),
		"algorithms":     obj.Algorithms(),
		"curves":         obj.Curves(),
		"serverName":     obj.ServerName(),
		"contentType":    obj.ContentType,
		"messageVersion": obj.MessageVersion,

		"handshakeVersion":   obj.HandshakeVersion,
		"handShakeType":      obj.HandShakeType,
		"randomTime":         obj.RandomTime,
		"randomBytes":        obj.RandomBytes,
		"sessionId":          obj.SessionId,
		"cipherSuites":       obj.CipherSuites,
		"compressionMethods": obj.CompressionMethods,
		"extensions":         extensions,
	}
	return results
}

func ParseSpec(clienthello []byte) (clientHelloInfo *Spec, err error) {
	clientHelloInfo = new(Spec)
	clientHelloInfo.raw = clienthello
	plaintext := cryptobyte.String(clienthello)
	if !plaintext.ReadUint8(&clientHelloInfo.ContentType) {
		err = errors.New("contentType error")
		return
	}
	if !plaintext.ReadUint16(&clientHelloInfo.MessageVersion) {
		err = errors.New("tlsMinVersion error")
		return
	}
	//handShakeProtocol
	var handShakeProtocol cryptobyte.String
	if !plaintext.ReadUint16LengthPrefixed(&handShakeProtocol) {
		err = errors.New("handShakeProtocol error")
		return
	}
	if !handShakeProtocol.ReadUint8(&clientHelloInfo.HandShakeType) {
		err = errors.New("handShakeType error")
		return
	}
	//read  helloData
	var handShakeData cryptobyte.String
	if !handShakeProtocol.ReadUint24LengthPrefixed(&handShakeData) {
		err = errors.New("handShakeData error")
		return
	}
	if !handShakeData.ReadUint16(&clientHelloInfo.HandshakeVersion) {
		err = errors.New("tlsMaxVersion error")
		return
	}
	if !handShakeData.ReadUint32(&clientHelloInfo.RandomTime) {
		err = errors.New("randomTime error")
		return
	}
	if !handShakeData.ReadBytes(&clientHelloInfo.RandomBytes, 28) {
		err = errors.New("randomTime error")
		return
	}
	if !handShakeData.ReadUint8LengthPrefixed(&clientHelloInfo.SessionId) {
		err = errors.New("sessionId error")
		return
	}
	var cipherSuitesData cryptobyte.String
	if !handShakeData.ReadUint16LengthPrefixed(&cipherSuitesData) {
		err = errors.New("cipherSuites error")
		return
	}
	clientHelloInfo.CipherSuites = []uint16{}
	for !cipherSuitesData.Empty() {
		var cipherSuite uint16
		if cipherSuitesData.ReadUint16(&cipherSuite) {
			clientHelloInfo.CipherSuites = append(clientHelloInfo.CipherSuites, cipherSuite)
		}
	}
	if !handShakeData.ReadUint8LengthPrefixed(&clientHelloInfo.CompressionMethods) {
		err = errors.New("compressionMethods error")
		return
	}
	var extensionsData cryptobyte.String
	if !handShakeData.ReadUint16LengthPrefixed(&extensionsData) {
		err = errors.New("handShakeData error")
		return
	}
	clientHelloInfo.Extensions = []Extension{}
	clientHelloInfo.MapExtensions = make(map[uint16]cryptobyte.String)
	for !extensionsData.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if extensionsData.ReadUint16(&extension) && extensionsData.ReadUint16LengthPrefixed(&extData) {
			clientHelloInfo.Extensions = append(clientHelloInfo.Extensions, Extension{
				Type: extension,
				Data: extData,
			})
			clientHelloInfo.MapExtensions[extension] = extData
		}
	}

	return
}

func SerializeSpec(clientHelloInfo *Spec) ([]byte, error) {
	// Initialize a builder for constructing the serialized data
	var b cryptobyte.Builder

	// Add ContentType
	b.AddUint8(clientHelloInfo.ContentType)

	// Add MessageVersion
	b.AddUint16(clientHelloInfo.MessageVersion)

	// Create a nested builder for the handshake protocol
	var handshake cryptobyte.Builder
	handshake.AddUint8(clientHelloInfo.HandShakeType)

	// Create a nested builder for handshake data
	var handshakeData cryptobyte.Builder
	handshakeData.AddUint16(clientHelloInfo.HandshakeVersion)
	handshakeData.AddUint32(clientHelloInfo.RandomTime)
	handshakeData.AddBytes(clientHelloInfo.RandomBytes)
	handshakeData.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(clientHelloInfo.SessionId))
	})

	// Serialize CipherSuites
	handshakeData.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, suite := range clientHelloInfo.CipherSuites {
			b.AddUint16(suite)
		}
	})

	// Serialize CompressionMethods
	handshakeData.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(clientHelloInfo.CompressionMethods))
	})

	// Serialize Extensions
	handshakeData.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ext := range clientHelloInfo.Extensions {
			b.AddUint16(ext.Type)
			b.AddUint16LengthPrefixed(func(extB *cryptobyte.Builder) {
				extB.AddBytes([]byte(ext.Data))
			})
		}
	})

	// Add handshake data with 24-bit length prefix
	handshake.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handshakeData.BytesOrPanic())
	})

	// Add handshake protocol with 16-bit length prefix
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(handshake.BytesOrPanic())
	})

	// Generate the final serialized bytes
	serialized, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	return serialized, nil
}

func generateTlsInfo(text string) (*PeetTlsInfo, error) {
	var p = &PeetTlsInfo{}
	err := json.Unmarshal([]byte(text), p)
	return p, err
}

func GenerateSpec(info *PeetTlsInfo) (string, error) {
	res, err := createTempSpec()

	if err != nil {
		return "", err
	}
	fmt.Println(res.MapExtensions)
	exts := []Extension{
		{Type: getGreaseValue()},
	}
	reg, _ := regexp.Compile(" \\((\\d+)\\)")
	ja3Str := info.Tls.Ja3
	ja3Strs := strings.Split(ja3Str, ",")
	cipherSuites := []uint16{getGreaseValue()}

	if ja3Strs != nil && len(ja3Strs) > 0 {
		cipherLists := strings.Split(ja3Strs[1], "-")
		for i := 0; i < len(cipherLists); i++ {
			parseUint, err := strconv.ParseUint(cipherLists[i], 10, 16)
			if err != nil {
				logrus.Errorf("ParseUint err: %v", err)
				return "", err
			}
			cipherSuites = append(cipherSuites, uint16(parseUint))
		}
	}
	if len(cipherSuites) > 0 {
		logrus.Infof("cipher suites: %v", cipherSuites)
		//res.CipherSuites = cipherSuites
	}
	signAlog := strings.Split(info.Tls.Peetprint, "|")[3]
	signAloges := strings.Split(signAlog, "-")
	var signs cryptobyte.Builder

	if len(signAloges) > 0 {
		signs.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for i := 0; i < len(signAloges); i++ {
				parseUint, err := strconv.ParseUint(signAloges[i], 10, 16)
				if err != nil {
					logrus.Errorf("ParseAlgoUint err: %v", err)
				} else {
					b.AddUint16(uint16(parseUint))
				}
			}

		})
	}
	//info.Tls.Extensions = slice.Shuffle(info.Tls.Extensions)
	for _, ext := range info.Tls.Extensions {
		name := ext.Name
		if strings.Contains(name, "TLS_GREASE") {
			continue
		}

		submatch := reg.FindStringSubmatch(name)
		if len(submatch) > 0 {
			atoi, err := strconv.Atoi(submatch[1])
			if atoi == 41 {
				continue
			}
			if err != nil {
				return "", err
			}
			if atoi == 13 {
				//bytes, err := signs.Bytes()
				//
				//if err != nil {
				exts = append(exts, Extension{Type: uint16(atoi), Data: res.MapExtensions[uint16(atoi)]})
				//} else {
				//	fmt.Println(bytes)
				//	exts = append(exts, Extension{Type: uint16(atoi), Data: bytes})
				//}
			} else {
				exts = append(exts, Extension{Type: uint16(atoi), Data: res.MapExtensions[uint16(atoi)]})
			}
		}
	}
	exts = append(exts, Extension{Type: getGreaseValue()})
	res.Extensions = exts
	logrus.Debugf("exts: %v", exts)
	resBytes, err := SerializeSpec(res)
	return hex.EncodeToString(resBytes), err

}
func createTempSpec() (*Spec, error) {
	t := "16030106f2010006ee0303e2b1fea3885a74c0ddee25fe5535f68b55b5d09d48dd7683ce460ed3bd2235f22008c1e52d9ac1f4a7a7742af043999f1e33919ffc713bb8cfa46c02bbddd3331c00209a9a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006858a8a0000000a000c000a7a7a11ec001d00170018002b000706baba030403030000000e000c0000096c6f63616c686f737444690005000302683200230000003304ef04ed7a7a00010011ec04c014f1bb9b18a0ca8b77a292a89c4cc94371a28091917b5c9ed3c954ae4c289a5960038810200193515a4b19f14e8018532f721d395c321818b6365b0343306d68560d00bc676f515dd9879b8ed1bfcab12aac90a3c754a4354b0de2624d34f370f7404d37120ab9871d47c97c512b3ecdab78aca541349b2e823401f8551a245c833f2822fc395d89459223847924d230a3a32fbb10901c194ace4ca1b24260526a2902256c4ccb21b5a4077be3cd42da294bb5026d0843119aaf3ca741e3ea575ba1112ff6774d123cb233247b7c8a2a2a5d08d0b98b4cc35f0b89a697c68517cd8404a937a15f4424ca36a519bdf4785452549eb11f454ca0298034f9b4babd789039d2585208352f2359ed71883366af777cb56e3c4251a69ee4066a74b2aa64b4cc2cc9ae64a03cc26ac99a0acb5953a3ad53735057be92279f60a66398123a8bfb561138798a747ac0738a82e66516e3761536bbb288345db09ff21c79941731dae578b53683dc5563ed4a6c650b6f62a1bcdd955505c0c9294a5d0d3c068c90797584982c5185c0f783580876fa062fae89aed5ab8228f719d774cfdba577cbe5380e358282db4336eba91f7321a367c69266377482be35b636a319bcfba60d46e04ea1c32065f0ad63d5a40bb01f40d225c8d9ac5d3bb4626537d8acaab2d35a1b2438a4161c769684e3f948e828096962774105a5a2466725a876534315b7210ad02512d424747910c49d8c2c530548c66b43ae9c5d2bc149fb488f05f441047aced4db461d63bedfa25c5842754237304757b057f23e9b5baf287cba3bc219edb6a1ae153b06e6cfef837c408725a56021310574a18923dab0c5811b47ffd35e63b74b40b02dcd136ed4113a00da08bef7b2c468ac13909dc86ac6cb25c9414192ed1527f071020f242b9b8957c1f1a278d14f5493903aa51ddc9c74ea224a634906aef92f77242df98513b594691cc79774d851fdf6b60789125ac5c9677b12496a71442070ee09a6879952e60155146b2c1f959b952ab5cbc8896de5002f227b6c98bc50784f899aae7dbc57ef38559f5a4a0ab81be4a35fed37249db41cd8dacb6cdb74ab913aa0006d4f57142e5077476b3289a09924b8ab7f8cbc1e8c9ecd01a4a83852194551fe475a4c85c24197788abb3437133c3f45c4b0749a1fc404db976b3f97298fe563811c87d09958d5e647ca05340e94b306a1570334ba5c4ab4753692d3fb25c5a36f46960fc895135422b785f81048c043e745cd9ba9567646ad530363fb6211e36585e9ba41a9dbb3c0e54b8671cd44431bfba445bc2353128c72451b53f2f0ca70c3102b6a7bc4794c68a025d528ac43c101312868c58a09bbf203bcb518e2021f98a8acef3c8a45eb18b954c853733c3099c5d031a8add5812840a606370a19f86bccf5819125bbc558a3adca7605028c70d459604959f7958632838d8543600f482758900de01b854f78ce9038140684c89be91d4ffc753072854846768d98672c22b85caa372579798bb11f03777a77b70d064124d16916f39aa05cb87a5f4072659ca59d348fe08931ff187ec59b6b10e288079412c751768f1804a7f05b4ebb1d41a59ca38a14b54c6d12529d7ccba9ae8ce439343406df58e4c01c2998545d7695f0460001c1f58e0154b6d0fadc7851b8ef4da68c31fe16f20afc8c00f293e6d25077ffa7e934998ee0ff72e17376001d0020651456c0dd35e4bf10787db7a4dd0e731b880547c438f71ee81b931c302972340017000000120000000d0012001004030804040105030805050108060601ff01000100002d00020101000b00020100001b00030200020010000e000c02683208687474702f312e31000500050100000000fe0d00fa00000100011b002037808103cbe2495fd0cdfc72e2416c9bc2be72285f9a9ac7055e24793e29ec6e00d09626b113dedfc8dae2ae3bba46e831cbec39371570872beff0e0a01184ce766a435bdd49baebda3844eb2568d5bb26acb9e2bb3f1508d38ef433bcc226811abb466869f7ee0b5d1accbda9c0930cd4252efabd8e64e5fb35b039bae6bbcc6f039d1535e3479fa4ab2668cf7842b61668e35c351677c5f556e0153135aa208dd516140245613953d1c0f60ec10f32baa6f65d7b6e475dda6829ed1c91cde9dd936317d8100561eee208f76b2a64a5789a95f24c226a1dd5a4bf7f2a7797e7db7ab5173cf505f4a928bbeabee803ac710c9a9a000100"

	decodeString, err := hex.DecodeString(t)
	if err != nil {
		panic(err)
		return nil, err
	}
	spec, err := ParseSpec(decodeString)
	if err != nil {
		return nil, nil
	}
	return spec, err
}

func RandomJa3(template string) string {
	info, err := generateTlsInfo(template)
	if err != nil {
		panic(err)
	}
	generateSpec, err := GenerateSpec(info)
	if err != nil {
		panic(err)
	}
	//fmt.Println(generateSpec)
	return generateSpec
}

func TestDns(t *testing.T) {

}

var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
	0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
}

func getGreaseValue() uint16 {

	return greaseValues[rand.IntN(len(greaseValues))]
}
