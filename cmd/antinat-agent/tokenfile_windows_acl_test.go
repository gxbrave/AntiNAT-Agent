//go:build windows

package main

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func tokenACLForTest(t *testing.T, sids ...*windows.SID) *windows.ACL {
	t.Helper()
	var pinner runtime.Pinner
	t.Cleanup(pinner.Unpin)
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(sids))
	for _, sid := range sids {
		pinner.Pin(sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windowsFileFullControl,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	return acl
}

func tokenSecurityDescriptorForTest(t *testing.T, protected bool, sids ...*windows.SID) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.SetDACL(tokenACLForTest(t, sids...), true, false); err != nil {
		t.Fatal(err)
	}
	if protected {
		if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
			t.Fatal(err)
		}
	}
	return sd
}

func TestValidateWindowsTokenSecurityDescriptorMatchesInstallerServiceIdentities(t *testing.T) {
	owner, err := windows.StringToSid("S-1-5-19")
	if err != nil {
		t.Fatal(err)
	}
	service, err := windows.StringToSid("S-1-5-80-123-456-789-1011-1213")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		t.Fatal(err)
	}

	if err := validateWindowsTokenSecurityDescriptor(tokenSecurityDescriptorForTest(t, true, owner, service), owner, service); err != nil {
		t.Fatalf("installer protected two-ACE descriptor rejected: %v", err)
	}
	if err := validateWindowsTokenSecurityDescriptor(tokenSecurityDescriptorForTest(t, false, owner, service), owner, service); err == nil {
		t.Fatal("descriptor with DACL inheritance enabled accepted")
	}
	if err := validateWindowsTokenSecurityDescriptor(tokenSecurityDescriptorForTest(t, true, owner, service, unrelated), owner, service); err == nil {
		t.Fatal("descriptor with unrelated principal accepted")
	}
	if err := validateWindowsTokenSecurityDescriptor(tokenSecurityDescriptorForTest(t, true, owner, owner), owner, service); err == nil {
		t.Fatal("descriptor without restricted service SID accepted")
	}
}
