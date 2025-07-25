package models

import "github.com/miekg/dns"

var OpCodeMap = map[string]int{
	"QUERY":    dns.OpcodeQuery,
	"IQUERY":   dns.OpcodeIQuery,
	"STATUS":   dns.OpcodeStatus,
	"NOTIFY":   dns.OpcodeNotify,
	"UPDATE":   dns.OpcodeUpdate,
	"STATEFUL": dns.OpcodeStateful,
}

var QClassMap = map[string]uint16{
	"IN": dns.ClassINET,
	"CS": dns.ClassCSNET,
	"CH": dns.ClassCHAOS,
	"HS": dns.ClassHESIOD,
	"NO": dns.ClassNONE,
	"AN": dns.ClassANY,
}

var QTypeMap = map[string]uint16{
	// Common Resource Records
	"A":          dns.TypeA,
	"AAAA":       dns.TypeAAAA,
	"CNAME":      dns.TypeCNAME,
	"DNSKEY":     dns.TypeDNSKEY,
	"DS":         dns.TypeDS,
	"MX":         dns.TypeMX,
	"NS":         dns.TypeNS,
	"NSEC":       dns.TypeNSEC,
	"NSEC3":      dns.TypeNSEC3,
	"NSEC3PARAM": dns.TypeNSEC3PARAM,
	"PTR":        dns.TypePTR,
	"RRSIG":      dns.TypeRRSIG,
	"SOA":        dns.TypeSOA,
	"SRV":        dns.TypeSRV,
	"SSHFP":      dns.TypeSSHFP,
	"TLSA":       dns.TypeTLSA,
	"TXT":        dns.TypeTXT,
	"CAA":        dns.TypeCAA,
	"URI":        dns.TypeURI,

	// Other Standard and Less Common Records
	"AFSDB":      dns.TypeAFSDB,
	"APL":        dns.TypeAPL,
	"AVC":        dns.TypeAVC,
	"CDS":        dns.TypeCDS,
	"CDNSKEY":    dns.TypeCDNSKEY,
	"CERT":       dns.TypeCERT,
	"CSYNC":      dns.TypeCSYNC,
	"DHCID":      dns.TypeDHCID,
	"DLV":        dns.TypeDLV,
	"DNAME":      dns.TypeDNAME,
	"EUI48":      dns.TypeEUI48,
	"EUI64":      dns.TypeEUI64,
	"GPOS":       dns.TypeGPOS,
	"HINFO":      dns.TypeHINFO,
	"HIP":        dns.TypeHIP,
	"HTTPS":      dns.TypeHTTPS,
	"IPSECKEY":   dns.TypeIPSECKEY,
	"ISDN":       dns.TypeISDN,
	"KEY":        dns.TypeKEY,
	"KX":         dns.TypeKX,
	"L32":        dns.TypeL32,
	"L64":        dns.TypeL64,
	"LOC":        dns.TypeLOC,
	"LP":         dns.TypeLP,
	"MINFO":      dns.TypeMINFO,
	"NAPTR":      dns.TypeNAPTR,
	"NID":        dns.TypeNID,
	"NINFO":      dns.TypeNINFO,
	"OPENPGPKEY": dns.TypeOPENPGPKEY,
	"PX":         dns.TypePX,
	"RP":         dns.TypeRP,
	"RT":         dns.TypeRT,
	"SMIMEA":     dns.TypeSMIMEA,
	"SPF":        dns.TypeSPF,
	"SVCB":       dns.TypeSVCB,
	"TA":         dns.TypeTA,
	"TALINK":     dns.TypeTALINK,
	"TKEY":       dns.TypeTKEY,
	"TSIG":       dns.TypeTSIG,
	"UNSPEC":     dns.TypeUNSPEC,
	"ZONEMD":     dns.TypeZONEMD,

	// Obsolete or Historical Records
	"ATMA":    dns.TypeATMA,
	"EID":     dns.TypeEID,
	"GID":     dns.TypeGID,
	"MAILA":   dns.TypeMAILA,
	"MAILB":   dns.TypeMAILB,
	"MD":      dns.TypeMD,
	"MF":      dns.TypeMF,
	"MG":      dns.TypeMG,
	"MR":      dns.TypeMR,
	"NIMLOC":  dns.TypeNIMLOC,
	"NSAPPTR": dns.TypeNSAPPTR,
	"NXT":     dns.TypeNXT,
	"UID":     dns.TypeUID,
	"UINFO":   dns.TypeUINFO,
	"X25":     dns.TypeX25,
	"NULL":    dns.TypeNULL,

	// Meta Query Types (used in questions, not as records)
	"ANY":  dns.TypeANY,
	"AXFR": dns.TypeAXFR,
	"IXFR": dns.TypeIXFR,
	"OPT":  dns.TypeOPT,
}
