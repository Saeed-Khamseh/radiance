//go:build !novpn

package vpn

import (
    "context"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/http/httptest"
    "net/netip"
    "strconv"
    "strings"
    "testing"
    "time"

    box "github.com/getlantern/lantern-box"
    "github.com/miekg/dns"
    sbox "github.com/sagernet/sing-box"
    "github.com/sagernet/sing-box/adapter"
    O "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing/common/json"
    "github.com/sagernet/sing/service"
    "github.com/stretchr/testify/require"
    "golang.org/x/net/proxy"

    rlog "github.com/getlantern/radiance/log"
)

func TestCIDRFakeIPHostnameFlow(t *testing.T) {
    target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprint(w, "CIDR bypass reached")
    }))
    defer target.Close()
    _, targetPort, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
    require.NoError(t, err)
    port, err := strconv.Atoi(targetPort)
    require.NoError(t, err)

    listener, err := net.Listen("tcp", "127.0.0.1:0")
    require.NoError(t, err)
    proxyPort := listener.Addr().(*net.TCPAddr).Port
    require.NoError(t, listener.Close())

    dir := t.TempDir()
    st, err := NewSplitTunnelHandler(dir, rlog.NoOpLogger())
    require.NoError(t, err)
    require.NoError(t, st.AddItem(TypeIPCIDR, "127.0.0.0/8"))
    require.NoError(t, st.SetEnabled(true))

    ctx := box.Context(context.Background())
    opts, err := json.UnmarshalExtendedContext[O.Options](ctx, []byte(fmt.Sprintf(`{
        "log": {"disabled": true},
        "dns": {
            "servers": [
                {"type":"hosts","tag":"dns_remote","predefined":{"cidr-route.test":["127.0.0.1"]}},
                {"type":"fakeip","tag":"dns_fakeip","inet4_range":"198.18.0.0/15"}
            ],
            "rules":[{"query_type":["A"],"action":"route","server":"dns_fakeip"}],
            "final":"dns_remote"
        },
        "inbounds":[{"type":"mixed","tag":"test-in","listen":"127.0.0.1","listen_port":%d}],
        "outbounds":[{"type":"direct","tag":"direct"}]
    }`, proxyPort)))
    require.NoError(t, err)
    rules := append(cidrResolveRoutingRules(), splitTunnelRoutingRules()...)
    opts.Route = &O.RouteOptions{
        Rules: append(rules, catchAllBlockerRule()),
        RuleSet: splitTunnelRuleSet(dir),
    }
    instance, err := sbox.New(sbox.Options{Context: ctx, Options: opts})
    require.NoError(t, err)
    require.NoError(t, instance.Start())
    defer instance.Close()

    dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
    require.NotNil(t, dnsRouter)
    query := new(dns.Msg)
    query.SetQuestion("cidr-route.test.", dns.TypeA)
    reply, err := dnsRouter.Exchange(ctx, query, adapter.DNSQueryOptions{})
    require.NoError(t, err)
    var fake netip.Addr
    for _, answer := range reply.Answer {
        if a, ok := answer.(*dns.A); ok {
            fake, _ = netip.AddrFromSlice(a.A.To4())
        }
    }
    require.True(t, netip.MustParsePrefix("198.18.0.0/15").Contains(fake))

    dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, &net.Dialer{Timeout: time.Second})
    require.NoError(t, err)
    transport := &http.Transport{
        DisableKeepAlives: true,
        DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
            return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
        },
    }
    defer transport.CloseIdleConnections()
    client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
    address := fmt.Sprintf("http://%s:%d/", fake, port)
    reachesTarget := func() bool {
        response, err := client.Get(address)
        if err != nil { return false }
        defer response.Body.Close()
        body, err := io.ReadAll(response.Body)
        return err == nil && string(body) == "CIDR bypass reached"
    }
    require.True(t, reachesTarget(), "a fake-IP connection must resolve before matching the excluded CIDR")
    require.NoError(t, st.SetEnabled(false))
    require.Eventually(t, func() bool { return !reachesTarget() }, 5*time.Second, 50*time.Millisecond)
    require.NoError(t, st.SetEnabled(true))
    require.Eventually(t, reachesTarget, 5*time.Second, 50*time.Millisecond)
    require.NoError(t, st.RemoveItem(TypeIPCIDR, "127.0.0.0/8"))
    require.Eventually(t, func() bool { return !reachesTarget() }, 5*time.Second, 50*time.Millisecond)
}
