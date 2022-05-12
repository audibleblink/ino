package winacl

import (
	"fmt"
	"strings"

	"github.com/audibleblink/bamflags"
)

// AceType is the type of ACE as defined by Microsoft here:
// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries
type AceType byte

const (
	AceTypeAccessAllowed AceType = iota
	AceTypeAccessDenied
	AceTypeSystemAudit
	AceTypeSystemAlarm
	AceTypeAccessAllowedCompound
	AceTypeAccessAllowedObject
	AceTypeAccessDeniedObject
	AceTypeSystemAuditObject
	AceTypeSystemAlarmObject
	AceTypeAccessAllowedCallback
	AceTypeAccessDeniedCallback
	AceTypeAccessAllowedCallbackObject
	AceTypeAccessDeniedCallbackObject
	AceTypeSystemAuditCallback
	AceTypeSystemAlarmCallback
	AceTypeSystemAuditCallbackObject
	AceTypeSystemAlarmCallbackObject
)

// ACETypeLookup maps AceTypes to a human-readable labels
var ACETypeLookup = map[AceType]string{
	AceTypeAccessAllowed:               "ACCESS_ALLOWED",
	AceTypeAccessDenied:                "ACCESS_DENIED",
	AceTypeSystemAudit:                 "SYSTEM_AUDIT",
	AceTypeSystemAlarm:                 "SYSTEM_ALARM",
	AceTypeAccessAllowedCompound:       "ACCESS_ALLOWED_COMPOUND",
	AceTypeAccessAllowedObject:         "ACCESS_ALLOWED_OBJECT",
	AceTypeAccessDeniedObject:          "ACCESS_DENIED_OBJECT",
	AceTypeSystemAuditObject:           "SYSTEM_AUDIT_OBJECT",
	AceTypeSystemAlarmObject:           "SYSTEM_ALARM_OBJECT",
	AceTypeAccessAllowedCallback:       "ACCESS_ALLOWED_CALLBACK",
	AceTypeAccessDeniedCallback:        "ACCESS_DENIED_CALLBACK",
	AceTypeAccessAllowedCallbackObject: "ACCESS_ALLOWED_CALLBACK_OBJECT",
	AceTypeAccessDeniedCallbackObject:  "ACCESS_DENIED_CALLBACK_OBJECT",
	AceTypeSystemAuditCallback:         "SYSTEM_AUDIT_CALLBACK",
	AceTypeSystemAlarmCallback:         "SYSTEM_ALARM_CALLBACK",
	AceTypeSystemAuditCallbackObject:   "SYSTEM_AUDIT_CALLBACK_OBJECT",
	AceTypeSystemAlarmCallbackObject:   "SYSTEM_ALARM_CALLBACK_OBJECT",
}

// AceHeadFlags is a type representing an ACEs header
type ACEHeaderFlags byte

const (
	ACEHeaderFlagsObjectInheritAce        ACEHeaderFlags = 0x01
	ACEHeaderFlagsContainerInheritAce                    = 0x02
	ACEHeaderFlagsNoPropogateInheritAce                  = 0x04
	ACEHeaderFlagsInheritOnlyAce                         = 0x08
	ACEHeaderFlagsInheritedAce                           = 0x10
	ACEHeaderFlagsSuccessfulAccessAceFlag                = 0x40
	ACEHeaderFlagsFailedAccessAceFlag                    = 0x80
)

var ACEHeaderFlagLookup = map[ACEHeaderFlags]string{
	ACEHeaderFlagsObjectInheritAce:        "OBJECT_INHERIT_ACE",
	ACEHeaderFlagsContainerInheritAce:     "CONTAINER_INHERIT_ACE",
	ACEHeaderFlagsNoPropogateInheritAce:   "NO_PROPOGATE_INHERIT_ACE",
	ACEHeaderFlagsInheritOnlyAce:          "INHERIT_ONLY_ACE",
	ACEHeaderFlagsInheritedAce:            "INHERITED_ACE",
	ACEHeaderFlagsSuccessfulAccessAceFlag: "SUCCESSFUL_ACCESS_ACE_FLAG",
	ACEHeaderFlagsFailedAccessAceFlag:     "FAILED_ACCESS_ACE_FLAG",
}

// ACEInheritanceFlags is a type representing an ACEs inheritance flags
type ACEInheritanceFlags uint32

const (
	ACEInheritanceFlagsObjectTypePresent          ACEInheritanceFlags = 0x01
	ACEInheritanceFlagsInheritedObjectTypePresent                     = 0x02
)

// ACEInheritanceFlagsLookup maps ACEInheritanceFlags to a human-readable labels
var ACEInheritanceFlagsLookup = map[ACEInheritanceFlags]string{
	ACEInheritanceFlagsObjectTypePresent:          "ACE_OBJECT_TYPE_PRESENT",
	ACEInheritanceFlagsInheritedObjectTypePresent: "ACE_INHERITED_OBJECT_TYPE_PRESENT",
}

// ACEAccessMask represents an ACE's permissions
type ACEAccessMask struct {
	value uint32
}

const (
	AccessMaskGenericRead    = 0x80000000
	AccessMaskGenericWrite   = 0x40000000
	AccessMaskGenericExecute = 0x20000000
	AccessMaskGenericAll     = 0x10000000
	AccessMaskMaximumAllowed = 0x02000000
	AccessMaskSystemSecurity = 0x01000000
	AccessMaskSynchronize    = 0x00100000
	AccessMaskWriteOwner     = 0x00080000
	AccessMaskWriteDACL      = 0x00040000
	AccessMaskReadControl    = 0x00020000
	AccessMaskDelete         = 0x00010000

	// Advances ACE Masks
	ADSRightDSControlAccess = 0x00000100
	ADSRightDSListObject    = 0x00000080
	ADSRightDSDeleteTree    = 0x00000040
	ADSRightDSWriteProp     = 0x00000020
	ADSRightDSReadProp      = 0x00000010
	ADSRightDSSelf          = 0x00000008
	ADSRightDSListChildrend = 0x00000004
	ADSRightDSDeleteChild   = 0x00000002
	ADSRightDSCreateChild   = 0x00000001
)

// ACEAccessMaskLookup maps ACEAccessMasks to a human-readable labels
var ACEAccessMaskLookup = map[uint32]string{
	AccessMaskGenericRead:    "GENERIC_READ",
	AccessMaskGenericWrite:   "GENERIC_WRITE",
	AccessMaskGenericExecute: "GENERIC_EXECUTE",
	AccessMaskGenericAll:     "GENERIC_ALL",
	AccessMaskMaximumAllowed: "MAXIMUM_ALLOWED",
	AccessMaskSystemSecurity: "SYSTEM_SECURITY",
	AccessMaskSynchronize:    "SYNCHRONIZE",
	AccessMaskWriteOwner:     "WRITE_OWNER",
	AccessMaskWriteDACL:      "WRITE_DACL",
	AccessMaskReadControl:    "READ_CONTROL",
	AccessMaskDelete:         "DELETE",

	// Advanced ACEs
	ADSRightDSControlAccess: "CONTROL_ACCESS",
	ADSRightDSWriteProp:     "WRITE_PROP",
	ADSRightDSReadProp:      "READ_PROP",
	ADSRightDSSelf:          "SELF",
	ADSRightDSDeleteChild:   "DELETE_CHILD",
	ADSRightDSCreateChild:   "CREATE_CHILD",
}

// Raw returns an ACEAccessMask's uint32 Access Mask
func (am ACEAccessMask) Raw() uint32 {
	return am.value
}

// String returns an ACEAccessMask's human-readable Access Mask
func (am ACEAccessMask) String() string {
	readableRights := am.StringSlice()
	return strings.Join(readableRights, " ")
}

// StringSlice, like String, returns human-readable permissions,
// except as a slice of string
func (am ACEAccessMask) StringSlice() []string {
	var readableRights []string
	rights, _ := bamflags.ParseInt(int64(am.value))

	for _, right := range rights {
		if perm := ACEAccessMaskLookup[uint32(right)]; perm != "" {
			readableRights = append(readableRights, perm)
		}
	}
	return readableRights
}

// ACE represents an ACE within an ACL
type ACE struct {
	//Header + AccessMask is 16 bytes
	Header     ACEHeader
	AccessMask ACEAccessMask
	ObjectAce  ObjectAce
}

// Strings returns an human-readable representation of an ACE
func (s ACE) String() string {
	sb := strings.Builder{}

	aceType := s.GetTypeString()
	perms := s.AccessMask.String()
	var sid SID

	sb.WriteString(fmt.Sprintf("AceType: %s\n", aceType))

	switch s.ObjectAce.(type) {
	case BasicAce:
		sb.WriteString(fmt.Sprintf("Flags: %s\n", s.Header.FlagsString()))
		sid = s.ObjectAce.GetPrincipal()

	case AdvancedAce:
		aa := s.ObjectAce.(AdvancedAce)
		sid = aa.GetPrincipal()

		switch aa.Flags {
		case ACEInheritanceFlagsObjectTypePresent:
			sb.WriteString(fmt.Sprintf("ObjectType: %s\n", aa.ObjectType.Resolve()))
		case ACEInheritanceFlagsInheritedObjectTypePresent:
			sb.WriteString(fmt.Sprintf("InheritedObjectType: %s\n", aa.InheritedObjectType.Resolve()))
		}
	}

	sb.WriteString(fmt.Sprintf("Permissions: %s\n", perms))
	return fmt.Sprintf("SID: %s\n%s", sid.String(), sb.String())
}

// ACEHeader represents an ACE Header
type ACEHeader struct {
	Type  AceType
	Flags ACEHeaderFlags
	Size  uint16
}

// FlagsString returns an human-readable representation of an ACEHeader's Flags
func (ah ACEHeader) FlagsString() string {
	var readableFlags []string
	flags, _ := bamflags.ParseInt(int64(ah.Flags))
	for _, flag := range flags {
		headerFlag := ACEHeaderFlags(flag)
		f := ACEHeaderFlagLookup[headerFlag]
		readableFlags = append(readableFlags, f)
	}
	return strings.Join(readableFlags, " ")
}

// ACEObjectType holds information and an ACE's Object Type. A GUID
type ACEObjectType struct {
	PartA uint32
	PartB uint16
	PartC uint16
	PartD [8]byte
}

// GetType returns the ACE type, fetched from the ACE Header
func (s ACE) GetType() AceType {
	return s.Header.Type
}

// GetTypeString returns the ACE type as a human-readable string
func (s ACE) GetTypeString() string {
	return ACETypeLookup[s.Header.Type]
}

// BasicAce represent a Simple ACEs
type BasicAce struct {
	SecurityIdentifier SID
}

// GetPrincipal returns an ACEs Principal
func (s BasicAce) GetPrincipal() SID {
	return s.SecurityIdentifier
}

//AdvancedAce represents an Object Ace
type AdvancedAce struct {
	Flags               ACEInheritanceFlags //4 bytes
	ObjectType          GUID                //16 bytes
	InheritedObjectType GUID
	SecurityIdentifier  SID
}

// GetPrincipal returns an ACEs Principal
func (s AdvancedAce) GetPrincipal() SID {
	return s.SecurityIdentifier
}

// FlagsString returns an human-readable representation of an ACEHeader's Flags
func (s AdvancedAce) FlagsString() string {
	sb := strings.Builder{}
	flags, _ := bamflags.ParseInt(int64(s.Flags))
	for _, flag := range flags {
		aaf := ACEInheritanceFlags(flag)
		f := ACEInheritanceFlagsLookup[aaf]
		fmt.Fprintf(&sb, "%s ", f)
	}
	return sb.String()
}

// ObjectAce is an interface that defines what constitutes an ACE within
// go-winacl
type ObjectAce interface {
	GetPrincipal() SID
}
