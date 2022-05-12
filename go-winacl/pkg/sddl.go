package winacl

import (
	"fmt"
	"strings"

	"github.com/audibleblink/bamflags"
)

// AceHeaderTypeSDDL is a map of AceTypes matched to their
// corresponding SDDL abbreviations
var AceHeaderTypeSDDL = map[AceType]string{
	AceTypeAccessAllowed:               "A",
	AceTypeAccessDenied:                "D",
	AceTypeSystemAudit:                 "AU",
	AceTypeSystemAlarm:                 "AL",
	AceTypeAccessAllowedCompound:       "",
	AceTypeAccessAllowedObject:         "OA",
	AceTypeAccessDeniedObject:          "OD",
	AceTypeSystemAuditObject:           "OU",
	AceTypeSystemAlarmObject:           "OL",
	AceTypeAccessAllowedCallback:       "XA",
	AceTypeAccessDeniedCallback:        "XD",
	AceTypeAccessAllowedCallbackObject: "",
	AceTypeAccessDeniedCallbackObject:  "",
	AceTypeSystemAuditCallback:         "XU",
	AceTypeSystemAlarmCallback:         "",
	AceTypeSystemAuditCallbackObject:   "",
	AceTypeSystemAlarmCallbackObject:   "",
}

// AceHeaderFlagsSDDL is a map of AceHeaderFlags matched to
// their corresponding SDDL abbreviations
var AceHeaderFlagsSDDL = map[ACEHeaderFlags]string{
	ACEHeaderFlagsObjectInheritAce:        "OI",
	ACEHeaderFlagsContainerInheritAce:     "CI",
	ACEHeaderFlagsNoPropogateInheritAce:   "NP",
	ACEHeaderFlagsInheritOnlyAce:          "IO",
	ACEHeaderFlagsInheritedAce:            "ID",
	ACEHeaderFlagsSuccessfulAccessAceFlag: "SA",
	ACEHeaderFlagsFailedAccessAceFlag:     "FA",
}

// AceRightsSDDL is a map of permission masks, mapped to their
// corresponding SDDL abbreviations
var AceRightsSDDL = map[uint32]string{
	AccessMaskGenericRead:    "GR",
	AccessMaskGenericWrite:   "GW",
	AccessMaskGenericExecute: "GX",
	AccessMaskGenericAll:     "GA",
	AccessMaskWriteOwner:     "WO",
	AccessMaskWriteDACL:      "WD",
	AccessMaskReadControl:    "RC",
	AccessMaskDelete:         "SD",

	// Advanced ACEs
	ADSRightDSReadProp:      "RP",
	ADSRightDSWriteProp:     "WP",
	ADSRightDSCreateChild:   "CC",
	ADSRightDSDeleteChild:   "DC",
	ADSRightDSListChildrend: "LC",
	ADSRightDSSelf:          "SW",
	ADSRightDSListObject:    "LO",
	ADSRightDSDeleteTree:    "DT",
	ADSRightDSControlAccess: "CR",
}

// https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
const (
	ControlDACLAutoInheritReq = 0x100
	ControlDACLAutoInherit    = 0x400
	ControlDACLProtected      = 0x1000
)

// NtSecurityDescriptorHeaderSDDL holds the Security Descriptor
// Control property mapped to its corresponding SDDL abbreviations
// NOTE: ntsd.ToSDDL() relies on these being the only 3 entries
// in this map.
var NtSecurityDescriptorHeaderSDDL = map[int]string{
	ControlDACLAutoInheritReq: "AR",
	ControlDACLAutoInherit:    "AI",
	ControlDACLProtected:      "P",
}

// WellKnownSIDsSSDL is a map of common Windows SIDs mapped to
// their corresponding abbreviations
var WellKnownSIDsSSDL = map[string]string{
	"S-1-1-0":            "WD",
	"S-1-3-0":            "CO",
	"S-1-3-1":            "CG",
	"S-1-3-4":            "OW",
	"S-1-5-2":            "NU",
	"S-1-5-4":            "IU",
	"S-1-5-6":            "SU",
	"S-1-5-7":            "AN",
	"S-1-5-9":            "ED",
	"S-1-5-10":           "PS",
	"S-1-5-11":           "AU",
	"S-1-5-12":           "RC",
	"S-1-5-18":           "SY",
	"S-1-5-19":           "LS",
	"S-1-5-20":           "NS",
	"S-1-5-33":           "WR",
	"S-1-5-32-544":       "BA",
	"S-1-5-32-545":       "BU",
	"S-1-5-32-546":       "BG",
	"S-1-5-32-547":       "PU",
	"S-1-5-32-548":       "AO",
	"S-1-5-32-549":       "SO",
	"S-1-5-32-550":       "PO",
	"S-1-5-32-551":       "BO",
	"S-1-5-32-552":       "RE",
	"S-1-5-32-554":       "RU",
	"S-1-5-32-555":       "RD",
	"S-1-5-32-556":       "NO",
	"S-1-5-32-558":       "MU",
	"S-1-5-32-559":       "LU",
	"S-1-5-32-568":       "IS",
	"S-1-5-32-569":       "CY",
	"S-1-5-32-573":       "ER",
	"S-1-5-32-574":       "CD",
	"S-1-5-32-575":       "RA",
	"S-1-5-32-576":       "ES",
	"S-1-5-32-577":       "MS",
	"S-1-5-32-578":       "HA",
	"S-1-5-32-579":       "AA",
	"S-1-5-32-580":       "RM",
	"S-1-5-21-0-0-0-498": "RO",
	"S-1-5-21-0-0-0-500": "LA",
	"S-1-5-21-0-0-0-501": "LG",
	"S-1-5-21-0-0-0-512": "DA",
	"S-1-5-21-0-0-0-513": "DU",
	"S-1-5-21-0-0-0-514": "DG",
	"S-1-5-21-0-0-0-515": "DC",
	"S-1-5-21-0-0-0-516": "DD",
	"S-1-5-21-0-0-0-517": "CA",
	"S-1-5-21-0-0-0-518": "SA",
	"S-1-5-21-0-0-0-519": "EA",
	"S-1-5-21-0-0-0-520": "PA",
	"S-1-5-21-0-0-0-522": "CN",
	"S-1-5-21-0-0-0-553": "RS",
	"S-1-5-84-0-0-0-0-0": "UD",
	"S-1-15-2-1":         "AC",
	"S-1-16-4096":        "LW",
	"S-1-16-8192":        "ME",
	"S-1-16-8448":        "MP",
	"S-1-16-12288":       "HI",
	"S-1-16-16384":       "SI",
}

// RightsString returns the representation of an ACE's permissions,
// in SDDL format
func (s ACE) RightsString() string {
	sb := strings.Builder{}
	flags, _ := bamflags.ParseInt(int64(s.AccessMask.value))

	for _, flag := range flags {
		symbol := AceRightsSDDL[uint32(flag)]
		sb.WriteString(symbol)
	}
	return sb.String()
}

func (s ACEHeader) SDDLFlags() string {
	sb := strings.Builder{}
	flags, _ := bamflags.ParseInt(int64(s.Flags))

	for _, flag := range flags {
		fType := ACEHeaderFlags(flag)
		symbol := AceHeaderFlagsSDDL[fType]
		sb.WriteString(symbol)
	}
	return sb.String()
}

// ToSDDL will convert the individual components of an ACD
// into an SDDL compliant string
//
//https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings
func (s ACE) ToSDDL() string {
	format := "(%s;%s;%s;%s;%s;%s)"

	var (
		objGUID          string
		inheritedObjGUID string
	)

	switch s.ObjectAce.(type) {
	case AdvancedAce:
		aa := s.ObjectAce.(AdvancedAce)
		objGUID = aa.ObjectType.String()
		inheritedObjGUID = aa.InheritedObjectType.String()
	}

	accountSID := s.ObjectAce.GetPrincipal().String()
	if wellKnown := WellKnownSIDsSSDL[accountSID]; wellKnown != "" {
		accountSID = wellKnown
	}

	sddlString := fmt.Sprintf(format,
		AceHeaderTypeSDDL[s.Header.Type], // AceType
		s.Header.SDDLFlags(),             // AceFlags
		s.RightsString(),                 // Rights
		objGUID,                          // ObjectGUID
		inheritedObjGUID,                 // Inherited Object GUID
		accountSID,                       // Account SID
		// "(attrs)",                        // Resource Attrs
	)
	return sddlString
}

// ToSDDL will convert the individual components of an ACD
// into an SDDL compliant string
func (a ACL) ToSDDL(flags string) string {
	sb := strings.Builder{}
	// TODO Change when SACLs are implemented
	sb.WriteString("D:")
	sb.WriteString(flags)
	for _, ace := range a.Aces {
		sb.WriteString(ace.ToSDDL())
	}
	return sb.String()
}

// ToSDDL will convert Control value of an NtSecurityDescriptorHeader
// into an SDDL compliant string
func (ndh NtSecurityDescriptorHeader) ToSDDL() string {
	// ControlDACLAutoInheritReq = 0x100 = AR
	// ControlDACLAutoInherit    = 0x400 = AI
	// ControlDACLProtected      = 0x1000 = P
	sb := strings.Builder{}
	flags, _ := bamflags.ParseInt(int64(ndh.Control))

	for _, flag := range flags {
		symbol := NtSecurityDescriptorHeaderSDDL[flag]
		sb.WriteString(symbol)
	}

	return sb.String()
}

// ToSDDL will convert the individual components of a NtSecurityDescriptor
// into an SDDL compliant string
//
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2918391b-75b9-4eeb-83f0-7fdc04a5c6c9
func (s NtSecurityDescriptor) ToSDDL() string {
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "O:%s", s.Owner.String())
	fmt.Fprintf(&sb, "G:%s", s.Group.String())
	sb.WriteString(s.DACL.ToSDDL(s.Header.ToSDDL()))
	return sb.String()
}
