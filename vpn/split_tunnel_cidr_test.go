//go:build !novpn

package vpn

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/radiance/common/atomicfile"
	"github.com/getlantern/radiance/internal"
	rlog "github.com/getlantern/radiance/log"
)

func TestCIDRValidationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	require.NoError(t, st.AddItem(TypeDomainSuffix, "example.com"))
	require.NoError(t, st.AddItems(SplitTunnelFilter{IPCIDR: []string{
		" 192.168.1.25/24 ", "192.168.1.0/24", "2001:db8::abcd/32", "::1/128",
	}}))
	want := []string{"192.168.1.0/24", "2001:db8::/32", "::1/128"}
	assert.Equal(t, want, st.Filters().IPCIDR)
	require.NoError(t, st.AddItem(TypeIPCIDR, "192.168.1.99/24"))
	assert.Equal(t, want, st.Filters().IPCIDR)

	st, err = NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Equal(t, want, st.Filters().IPCIDR)
	assert.Equal(t, []string{"example.com"}, st.Filters().DomainSuffix)

	require.NoError(t, st.RemoveItem(TypeIPCIDR, "192.168.1.42/24"))
	require.NoError(t, st.RemoveItems(SplitTunnelFilter{IPCIDR: []string{"2001:db8:abcd::/32", "::1/128"}}))
	st, err = NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Empty(t, st.Filters().IPCIDR)
	assert.Equal(t, []string{"example.com"}, st.Filters().DomainSuffix)
}

func TestCIDRRejectsInvalidBatchBeforeMutation(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.AddItem(TypeIPCIDR, "127.0.0.1/32"))
	for _, invalid := range []string{"127.0.0.1", "10.0.0.0/33", "::1/129", "localhost/32", "fe80::1%eth0/64", "1.2.3.999/24"} {
		t.Run(invalid, func(t *testing.T) {
			require.Error(t, st.AddItems(SplitTunnelFilter{
				Domain: []string{"must-not-be-added.test"},
				IPCIDR: []string{"192.0.2.0/24", invalid},
			}))
			assert.Empty(t, st.Filters().Domain)
			assert.Equal(t, []string{"127.0.0.1/32"}, st.Filters().IPCIDR)
			require.Error(t, st.AddItem(TypeIPCIDR, invalid))
			require.Error(t, st.RemoveItem(TypeIPCIDR, invalid))
		})
	}
}

func TestCIDRSaveFailureRestoresMemory(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.AddItem(TypeIPCIDR, "127.0.0.1/32"))
	gateBefore, err := os.ReadFile(st.resolverFile)
	require.NoError(t, err)
	st.ruleFile = filepath.Join(t.TempDir(), "missing", "split-tunnel.json")
	require.Error(t, st.AddItems(SplitTunnelFilter{IPCIDR: []string{"192.0.2.0/24"}}))
	assert.Equal(t, []string{"127.0.0.1/32"}, st.Filters().IPCIDR)
	gateAfter, err := os.ReadFile(st.resolverFile)
	require.NoError(t, err)
	assert.Equal(t, gateBefore, gateAfter)
	require.Error(t, st.RemoveItem(TypeIPCIDR, "127.0.0.1/32"))
	assert.Equal(t, []string{"127.0.0.1/32"}, st.Filters().IPCIDR)
}

func TestCIDRRoutesIPv4IPv6AndResolvedDomains(t *testing.T) {
	st := newSplitTunnel(t.TempDir(), rlog.NoOpLogger())
	require.NoError(t, st.AddItems(SplitTunnelFilter{IPCIDR: []string{"192.0.2.0/24", "2001:db8::/32"}}))
	require.NoError(t, st.SetEnabled(true))
	rule, waitReload := splitTunnelMatcher(t, st)
	for _, address := range []string{"192.0.2.0", "192.0.2.255", "2001:db8::1"} {
		metadata := &adapter.InboundContext{Destination: M.Socksaddr{Addr: netip.MustParseAddr(address), Port: 4200}}
		assert.True(t, rule.Match(metadata), address)
	}
	for _, address := range []string{"192.0.3.0", "2001:db9::1"} {
		metadata := &adapter.InboundContext{Destination: M.Socksaddr{Addr: netip.MustParseAddr(address), Port: 4200}}
		assert.False(t, rule.Match(metadata), address)
	}
	assert.True(t, rule.Match(&adapter.InboundContext{
		Domain:               "dev.example.test",
		DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.12")},
	}))
	require.NoError(t, st.SetEnabled(false))
	waitReload()
	assert.False(t, rule.Match(&adapter.InboundContext{Destination: M.Socksaddr{Addr: netip.MustParseAddr("192.0.2.1"), Port: 4200}}))
}

func TestCIDRLegacyRuleMigration(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, internal.SplitTunnelFileName)
	require.NoError(t, atomicfile.WriteFile(file, []byte(`{"version":3,"rules":[{"type":"logical","mode":"or","rules":[{"domain":"disable.rule"},{"ip_cidr":["192.0.2.0/24"],"domain_suffix":["example.com"]}]}]}`), 0o600))
	st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Equal(t, []string{"192.0.2.0/24"}, st.Filters().IPCIDR)
	assert.Equal(t, []string{"example.com"}, st.Filters().DomainSuffix)
	require.NoError(t, st.AddItem(TypeIPCIDR, "::1/128"))
	st, err = NewSplitTunnelHandler(dir, rlog.NoOpLogger())
	require.NoError(t, err)
	assert.Equal(t, []string{"192.0.2.0/24", "::1/128"}, st.Filters().IPCIDR)
}

