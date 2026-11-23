package rdplab

import "github.com/denyfirst/keybash/internal/terminalweb"

// The proxy names a refusal with two codes in its Ended frame
// (rdp-proxy/src/refusal.rs): the side that sent what it does not accept, and
// what. These are the words for them, the proxy's own list, code for code;
// TestProxyRefusalWordsMatchTheProxy reads the proxy's file and compares. A
// code outside them is "unknown". Only these words ever leave this package:
// nothing the proxy sends is shown or written as it came.
var proxySides = map[byte]string{1: "browser", 2: "windows", 3: "keybash"}

var proxyRefusals = map[byte]string{
	1:  "PDU framing",
	2:  "PDU size",
	3:  "MCS from Windows",
	4:  "MCS from the browser",
	5:  "data on a channel not allowed",
	6:  "joining a channel not allowed",
	7:  "no account for the Client Info",
	8:  "Client Info",
	9:  "Client Info asks for more than the desktop",
	10: "not an X.224 data PDU",
	11: "not an MCS Connect Response",
	12: "channel numbering",
	13: "static channel not allowed",
	14: "channel chunk",
	15: "channel chunk order",
	16: "dynamic channel PDU",
	17: "channel name",
	18: "dynamic channel reused",
	19: "create response",
	20: "opening a dynamic channel not allowed",
	21: "display layout fragmented or compressed",
	22: "data on a dynamic channel not open",
	23: "dynamic channel command",
	24: "display layout",
	25: "display layout outside the bounds",
	26: "clipboard chunk",
	27: "clipboard chunk order",
	28: "clipboard message too large",
	29: "clipboard message length",
	30: "clipboard capabilities",
	31: "clipboard format list",
	32: "clipboard request for anything but text",
	33: "clipboard requests unanswered",
	34: "clipboard response",
	35: "clipboard message not allowed",
	36: "clipboard before Windows' is open",
	37: "clipboard data nobody asked for",
	38: "clipboard format name",
	39: "clipboard message",
	40: "Connect Initial too large",
	41: "not an MCS Connect Initial",
	42: "the browser must have been told TLS",
	43: "desktop size outside the bounds",
	44: "device scale factor",
	45: "monitor layout",
	46: "encode",
	47: "RDCleanPath request",
	48: "RDCleanPath request too large",
	49: "RDCleanPath request changes the connection",
	50: "X.224 request",
	51: "security other than TLS",
	52: "X.224 confirm",
	53: "NLA not selected",
	54: "bytes before TLS",
	55: "certificate or TLS",
	56: "bytes after NLA",
	57: "Connect Initial",
	58: "handshake too slow",
	59: "gateway frame",
	60: "setup",
	61: "trust files",
	62: "proxy internal",
}

// proxyFrameRefused is the gateway's own refusal of what the proxy sent: a
// malformed frame, a kind the proxy never sends, or an end it cannot read.
var proxyFrameRefused = terminalweb.Refusal{Side: "keybash", What: "proxy frame"}

// proxyRefusal names a refusal's two codes with the words above.
func proxyRefusal(side, what byte) terminalweb.Refusal {
	r := terminalweb.Refusal{Side: proxySides[side], What: proxyRefusals[what]}
	if r.Side == "" {
		r.Side = "unknown"
	}
	if r.What == "" {
		r.What = "unknown"
	}
	return r
}
